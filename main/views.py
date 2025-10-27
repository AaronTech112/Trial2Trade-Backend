from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.conf import settings
from django.http import JsonResponse, HttpResponse
from django.urls import reverse
from django.templatetags.static import static
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import json
import csv
import os
import uuid
import time
from datetime import datetime
from django.utils import timezone
from .forms import RegisterForm
from django.contrib import messages
import logging

from .models import MT5Account, Purchase, CustomUser, RealPropRequest, Payout, Certificate

logger = logging.getLogger(__name__)
MYFXBOOK_HTTP_HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'}

class MyFxBookInvalidSession(Exception):
    pass

def server_matches(acc_server, server_name):
    """Return True if server matches, allowing brand-only server names (e.g., 'EXNESS')."""
    if not server_name:
        return True
    if acc_server is None:
        return False
    as_norm = str(acc_server).strip().lower()
    s_norm = str(server_name).strip().lower()
    if as_norm == s_norm:
        return True
    brand = s_norm.split('-', 1)[0]
    return as_norm == brand

def myfxbook_login(http: requests.Session, base_url: str | None = None, use_post: bool = False) -> str:
    """Login using a persistent HTTP session; return session token."""
    email = getattr(settings, 'MYFXBOOK_EMAIL', None)
    password = getattr(settings, 'MYFXBOOK_PASSWORD', None)
    if not email or not password:
        logger.error('MyFXBook credentials missing in settings. Configure MYFXBOOK_EMAIL and MYFXBOOK_PASSWORD.')
        raise ValueError('MyFXBook credentials not configured. Set MYFXBOOK_EMAIL and MYFXBOOK_PASSWORD.')
    base = base_url or getattr(settings, 'MYFXBOOK_BASE_URL', 'https://www.myfxbook.com')
    url = f'{base}/api/login.json'
    logger.info('Attempting MyFXBook login for email %s', email)
    if use_post:
        resp = http.post(url, data={'email': email, 'password': password}, timeout=10)
    else:
        resp = http.get(url, params={'email': email, 'password': password}, timeout=10)
    try:
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.exception('MyFXBook login HTTP error: %s', e)
        raise RuntimeError(f"MyFXBook login HTTP error: {e}")
    try:
        data = resp.json()
    except ValueError:
        logger.error('MyFXBook login returned non-JSON response. Body: %s', resp.text[:500])
        raise RuntimeError('MyFXBook login returned non-JSON response.')
    if data.get('error'):
        logger.error('MyFXBook login failed: %s', data.get('message', 'Unknown error'))
        raise ValueError(f"MyFXBook login failed: {data.get('message', 'Unknown error')}")
    session_token = data.get('session', '').strip()
    if not session_token:
        logger.error('MyFXBook login did not return a session token.')
        raise RuntimeError('MyFXBook login did not return a session token.')
    logger.info('MyFXBook login successful.')
    return session_token

def myfxbook_get_account_info(http: requests.Session, session: str, account_id: str, base_url: str | None = None):
    """Return single account information for given MyFXBook account id."""
    base = base_url or getattr(settings, 'MYFXBOOK_BASE_URL', 'https://www.myfxbook.com')
    url = f"{base}/api/get-account-information.json?session={session.strip()}&id={str(account_id).strip()}"
    resp = http.get(url, timeout=10)
    try:
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.exception('Failed to fetch MyFXBook account info: %s', e)
        raise RuntimeError(f"Failed to fetch MyFXBook account info: {e}")
    try:
        data = resp.json()
    except ValueError:
        logger.error('MyFXBook account info response was not valid JSON. Body: %s', resp.text[:500])
        raise RuntimeError('MyFXBook account info response was not valid JSON.')
    if data.get('error') or (isinstance(data.get('status'), str) and data.get('status').lower() == 'error'):
        msg = data.get('message', 'Unknown error')
        logger.error('Failed to get MyFXBook account info: %s', msg)
        logger.error(f"MyFXBook get_account_information failed. Status: {resp.status_code}, Response: {resp.text}")
        if isinstance(msg, str) and 'invalid session' in msg.lower():
            raise MyFxBookInvalidSession(msg)
        raise ValueError(f"Failed to get MyFXBook account info: {msg}")
    info = data.get('account') or {}
    return info


def myfxbook_fetch_account_info_with_retry(account_id: str):
    http = requests.Session()
    # Disable environment proxies and system trust to avoid DNS/proxy issues
    http.trust_env = False
    http.proxies = {}
    http.headers.update({'User-Agent': MYFXBOOK_HTTP_HEADERS.get('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36'),
                         'Accept': 'application/json'})
    retries = Retry(total=3, backoff_factor=1.0, status_forcelist=[429, 502, 503, 504], allowed_methods=["GET","POST"])
    http.mount("https://", HTTPAdapter(max_retries=retries))
    http.mount("http://", HTTPAdapter(max_retries=retries))

    session_token = None
    try:
        base1 = getattr(settings, 'MYFXBOOK_BASE_URL', 'https://www.myfxbook.com')
        session_token = myfxbook_login(http, base_url=base1, use_post=False)
        time.sleep(0.8)
        try:
            return myfxbook_get_account_info(http, session_token, account_id, base_url=base1)
        except MyFxBookInvalidSession:
            logger.warning('MyFXBook session invalid for account info; retrying with post/http.')
            try:
                myfxbook_logout(http, session_token, base_url=base1)
            except Exception:
                pass
            session_token = myfxbook_login(http, base_url=base1, use_post=True)
            time.sleep(0.6)
            try:
                return myfxbook_get_account_info(http, session_token, account_id, base_url=base1)
            except MyFxBookInvalidSession:
                base2 = 'http://www.myfxbook.com'
                session_token = myfxbook_login(http, base_url=base2, use_post=False)
                time.sleep(0.6)
                return myfxbook_get_account_info(http, session_token, account_id, base_url=base2)
    except Exception as e:
        logger.exception('Error fetching MyFXBook account info: %s', e)
        raise
    finally:
        if session_token:
            try:
                myfxbook_logout(http, session_token)
            except Exception:
                pass
            
def myfxbook_get_my_accounts(http: requests.Session, session: str, base_url: str | None = None):
    """Return accounts using a persistent HTTP session."""
    base = base_url or getattr(settings, 'MYFXBOOK_BASE_URL', 'https://www.myfxbook.com')
    url = f'{base}/api/get-my-accounts.json?session={session.strip()}'
    resp = http.get(url, timeout=10)
    try:
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.exception('Failed to fetch MyFXBook accounts: %s', e)
        raise RuntimeError(f"Failed to fetch MyFXBook accounts: {e}")
    try:
        data = resp.json()
    except ValueError:
        logger.error('MyFXBook accounts response was not valid JSON. Body: %s', resp.text[:500])
        raise RuntimeError('MyFXBook accounts response was not valid JSON.')
    if data.get('error') or (isinstance(data.get('status'), str) and data.get('status').lower() == 'error'):
        msg = data.get('message', 'Unknown error')
        logger.error('Failed to get MyFXBook accounts: %s', msg)
        logger.error(f"MyFXBook get_my_accounts failed. Status: {resp.status_code}, Response: {resp.text}")
        if isinstance(msg, str) and 'invalid session' in msg.lower():
            raise MyFxBookInvalidSession(msg)
        raise ValueError(f"Failed to get MyFXBook accounts: {msg}")
    accounts = data.get('accounts', [])
    logger.info('MyFXBook returned %d accounts.', len(accounts))
    return accounts


def myfxbook_logout(http: requests.Session, session: str, base_url: str | None = None):
    try:
        base = base_url or getattr(settings, 'MYFXBOOK_BASE_URL', 'https://www.myfxbook.com')
        url = f'{base}/api/logout.json?session={session}'
        http.get(url, timeout=5)
    except Exception:
        pass


def myfxbook_fetch_accounts_with_retry():
    """Login and fetch accounts once with cookie persistence; retry on invalid session."""
    http = requests.Session()
    # Disable environment proxies and system trust to avoid DNS/proxy issues
    http.trust_env = False
    http.proxies = {}
    http.headers.update({'User-Agent': MYFXBOOK_HTTP_HEADERS.get('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36'), 'Accept': 'application/json'})
    # Add robust retries for transient network errors
    retries = Retry(total=3, backoff_factor=1.0, status_forcelist=[429, 502, 503, 504], allowed_methods=["GET","POST"])
    http.mount("https://", HTTPAdapter(max_retries=retries))
    http.mount("http://", HTTPAdapter(max_retries=retries))
    session_token = None
    try:
        # First try with https and GET login
        base1 = getattr(settings, 'MYFXBOOK_BASE_URL', 'https://www.myfxbook.com')
        session_token = myfxbook_login(http, base_url=base1, use_post=False)
        time.sleep(1.0)
        try:
            return myfxbook_get_my_accounts(http, session_token, base_url=base1)
        except MyFxBookInvalidSession:
            logger.warning('MyFXBook session invalid on https/GET; retrying with new login.')
            try:
                myfxbook_logout(http, session_token, base_url=base1)
            except Exception:
                pass
            # Retry login once; if still invalid, try POST login and HTTP base
            session_token = myfxbook_login(http, base_url=base1, use_post=True)
            time.sleep(0.8)
            try:
                return myfxbook_get_my_accounts(http, session_token, base_url=base1)
            except MyFxBookInvalidSession:
                logger.warning('MyFXBook session invalid on https/POST; trying http base.')
                try:
                    myfxbook_logout(http, session_token, base_url=base1)
                except Exception:
                    pass
                base2 = 'http://www.myfxbook.com'
                session_token = myfxbook_login(http, base_url=base2, use_post=False)
                time.sleep(0.8)
                return myfxbook_get_my_accounts(http, session_token, base_url=base2)
        except Exception as e:
            raise
    except Exception as e:
        logger.exception('Error fetching MyFXBook accounts: %s', e)
        raise
    finally:
        if session_token:
            try:
                # Attempt logout on whichever base was last used (best-effort)
                myfxbook_logout(http, session_token)
            except Exception:
                pass


def update_account_data_from_myfxbook(account, accounts=None):
    """
    Fetch account metrics from MyFXBook and update MT5Account fields.
    Tries to match either by accountId (numeric) or login (string).
    """
    try:
        # If no accounts list provided, login and fetch once (with retry)
        if accounts is None:
            try:
                accounts = myfxbook_fetch_accounts_with_retry()
            except Exception as e:
                accounts = []
                logger.warning('Falling back to single-account info due to list fetch error: %s', e)

        # Attempt list-based match
        matched = None
        if accounts:
            login_str = str(account.login).strip()
            server_name = (account.server or '').strip() or None
            for acc in accounts:
                acc_id = acc.get('accountId')
                acc_login = acc.get('login')
                acc_server_raw = acc.get('server')
                if acc_server_raw is None:
                    acc_server = None
                elif isinstance(acc_server_raw, dict):
                    acc_server = (acc_server_raw.get('server') or acc_server_raw.get('name') or '').strip()
                else:
                    acc_server = str(acc_server_raw).strip()
                try:
                    if acc_id is not None and str(acc_id).strip() == login_str:
                        if server_matches(acc_server, server_name):
                            matched = acc
                            break
                except Exception:
                    pass
                if acc_login is not None and str(acc_login).strip() == login_str:
                    if server_matches(acc_server, server_name):
                        matched = acc
                        break

        # If not matched from list, try direct account info by login as id
        info = None
        if not matched:
            try:
                info = myfxbook_fetch_account_info_with_retry(str(account.login).strip())
            except Exception as e:
                logger.exception('MyFXBook direct account info failed for login %s: %s', account.login, e)

        # Choose source dict
        source = matched or info or None
        if not source:
            raise Exception(f"No matching MyFXBook account found for login {account.login}")

        from decimal import Decimal
        balance = source.get('balance')
        equity = source.get('equity')
        profit = source.get('profit')
        drawdown = source.get('drawdown')

        if account.initial_balance is None and balance is not None:
            try:
                account.initial_balance = Decimal(str(balance))
            except Exception:
                account.initial_balance = None

        def to_decimal(val, default):
            try:
                return Decimal(str(val)) if val is not None else default
            except Exception:
                return default

        account.balance = to_decimal(balance, account.balance)
        account.equity = to_decimal(equity, account.equity)
        account.profit = to_decimal(profit, account.profit)
        account.drawdown = to_decimal(drawdown, account.drawdown)
        account.last_updated = timezone.now()
        account.save()

        try:
            account.check_breach_status()
        except Exception:
            pass

        logger.info('Updated MyFXBook metrics for login %s: balance=%s equity=%s profit=%s drawdown=%s',
                    account.login, account.balance, account.equity, account.profit, account.drawdown)
        return True
    except Exception as e:
        logger.exception('Error updating account data for login %s: %s', getattr(account, 'login', 'unknown'), e)
        return False
    
@login_required(login_url='/login_user')
def dashboard_overview(request):
    # Fetch assigned MT5 accounts for the current user
    user_accounts = MT5Account.objects.filter(user=request.user, assigned=True).order_by('-assigned_date', '-id')

    # Update account data from MyFXBook API for each assigned account
    accounts_list = []
    if user_accounts.exists():
        try:
            accounts_list = myfxbook_fetch_accounts_with_retry()
        except Exception as e:
            logger.exception('Error fetching MyFXBook accounts list: %s', e)
            messages.error(request, f"Error fetching MyFXBook accounts: {str(e)}")
            accounts_list = []
        for account in user_accounts:
            try:
                update_account_data_from_myfxbook(account, accounts=accounts_list)
            except Exception as e:
                logger.exception('Error fetching MyFXBook data in overview for login %s: %s', account.login, e)
                messages.error(request, f"Error fetching account data: {str(e)}")

    # Compute simple overview metrics
    from decimal import Decimal
    total_balance = sum([(a.balance or Decimal('0')) for a in user_accounts], Decimal('0'))
    total_profit = sum([(a.profit or Decimal('0')) for a in user_accounts], Decimal('0'))
    active_accounts_count = user_accounts.filter(status='active').count()

    # Placeholder stats (no trade history model yet)
    win_rate = 0
    win_rate_change = 0
    profit_change = 0

    context = {
        'user_has_accounts': user_accounts.exists(),
        'user_accounts': user_accounts,
        'active_accounts_count': active_accounts_count,
        'total_balance': total_balance,
        'total_profit': total_profit,
        'win_rate': win_rate,
        'win_rate_change': win_rate_change,
        'profit_change': profit_change,
    }
    
    return render(request, 'main/dashboard_overview.html', context)


def register(request):
    if request.user.is_authenticated:
        return redirect('index')
    else:
        if request.method == 'POST':
            form = RegisterForm(request.POST)
            if form.is_valid():
                user = form.save(commit=False)
                user.save()  # Save the user before authenticating
                login(request, user)
                messages.success(request, f'Welcome, {user.username}! Your account has been created.')
                return redirect('index')
            else:
                messages.error(request, 'Error creating account. Please check the form.')
        else:
            form = RegisterForm()
    return render(request, 'main/register.html', {'form': form})       


def login_user(request):
    if request.user.is_authenticated:
        return redirect('index')
    else:
        error_message = None
        if request.method == 'POST':
            email = request.POST['email']
            password = request.POST['password']
            user = authenticate(request, email=email, password=password)

            if user is not None:
                login(request, user)
                return redirect('index')
            else:
                messages.error(request, 'Invalid email or password.')
        return render(request, 'main/login.html', {'error_message': error_message})


def logout_user(request):
    logout(request)
    return redirect('index')


def normalize_account_size(account_size):
    """Map various account_size inputs to MT5Account.ACCOUNT_SIZE_CHOICES values."""
    if account_size is None:
        return None
    s = str(account_size).strip().lower().replace(',', '').replace('$', '')
    # Convert '5k' to 5000, else try numeric
    val = None
    if s.endswith('k'):
        num = s[:-1]
        if num.isdigit():
            val = int(num) * 1000
    else:
        try:
            val = int(s)
        except ValueError:
            val = None
    mapping = {
        5000: '$5k',
        10000: '$10k',
        25000: '$25k',
        50000: '$50k',
    }
    return mapping.get(val)

def get_available_mt5_account(account_size=None):
    """
    Get an available MT5 account from the database
    """
    query = MT5Account.objects.filter(status='available', assigned=False)
    if account_size:
        normalized = normalize_account_size(account_size)
        if not normalized:
            return None
        query = query.filter(account_size=normalized)
    
    account = query.first()
    if not account:
        return None
        
    return {
        'account_size': account.account_size,
        'login': account.login,
        'password': account.password,
        'server': account.server
    }



@login_required(login_url='/login_user')
def dashboard_purchase(request):
    # If POST, prepare checkout with tx_ref and pending purchase
    if request.method == 'POST':
        account_size = request.POST.get('account_size')
        amount = request.POST.get('amount')
        currency = 'NGN'

        if not account_size or not amount:
            messages.error(request, 'Please select an account size and enter amount.')
            return redirect('dashboard_purchase')

        # Check if account size is available
        normalized_size = normalize_account_size(account_size)
        if not normalized_size or not MT5Account.objects.filter(status='available', assigned=False, account_size=normalized_size).exists():
            messages.error(request, f'No {normalized_size or account_size} accounts available at the moment. Please try another account size.')
            return redirect('dashboard_purchase')

        # Generate unique transaction reference
        tx_ref = f"txn-{uuid.uuid4().hex[:10]}"

        # Create pending purchase record
        Purchase.objects.create(
            user=request.user,
            tx_ref=tx_ref,
            amount=amount,
            payment_status='pending',
            verified=False,
        )

        # Get Flutterwave secret key
        secret_key = settings.FLUTTERWAVE_SECRET_KEY or 'FLWSECK_TEST-732a1c10a2c6dbcff4fc8bf7da4942a3-X'

        # Build absolute redirect URL for payment verification callback
        redirect_url = request.build_absolute_uri(reverse('payment_callback'))

        # Prepare payment payload for Flutterwave
        payload = {
            'tx_ref': tx_ref,
            'amount': amount,
            'currency': currency,
            'redirect_url': redirect_url,
            'meta': {'account_size': account_size},
            'customer': {
                'email': request.user.email,
                'name': request.user.get_full_name() or request.user.username,
                'phonenumber': getattr(request.user, 'phone_number', '')
            },
            'customizations': {
                'title': 'Trail2Fund Purchase',
                'description': f'Purchase {account_size} account',
                'logo': request.build_absolute_uri(static('images/logo.png'))
            },
            'payment_options': "card,banktransfer,ussd,account,mpesa,mobilemoneyghana,mobilemoneyrwanda,mobilemoneyzambia,mobilemoneyuganda,mobilemoneytanzania,qr,credit",
            'payment_plan': None,
            'locale': "auto",
            'include_discount': True
        }

        # Make API call to Flutterwave to create payment
        headers = {
            'Authorization': f'Bearer {secret_key}',
            'Content-Type': 'application/json',
        }
        try:
            # Set a timeout to prevent hanging requests
            response = requests.post(
                'https://api.flutterwave.com/v3/payments',
                json=payload,
                headers=headers,
                timeout=10  # 10 seconds timeout
            )
            response_data = response.json()

            if response.status_code == 200 and response_data.get('status') == 'success':
                # Get payment link from response
                payment_link = response_data['data']['link']
                context = {
                    'tx_ref': tx_ref,
                    'amount': amount,
                    'currency': currency,
                    'account_size': account_size,
                    'payment_link': payment_link
                }
                return render(request, 'main/payment-checkout.html', context)
            else:
                error_msg = response_data.get('message', 'Failed to initiate payment. Please try again.')
                messages.error(request, error_msg)
                return redirect('dashboard_purchase')
        except requests.exceptions.ConnectionError as e:
            messages.error(request, f"Payment initiation error: Unable to connect to payment gateway. Please check your internet connection and try again.")
            return redirect('dashboard_purchase')
        except requests.exceptions.Timeout as e:
            messages.error(request, f"Payment initiation error: Connection to payment gateway timed out. Please try again later.")
            return redirect('dashboard_purchase')
        except requests.exceptions.RequestException as e:
            messages.error(request, f"Payment initiation error: {str(e)}")
            return redirect('dashboard_purchase')
        except Exception as e:
            messages.error(request, f"An unexpected error occurred: {str(e)}")
            return redirect('dashboard_purchase')

    # Show purchase page with available account sizes
    public_key = settings.FLUTTERWAVE_PUBLIC_KEY or 'FLWPUBK_TEST-bcdf22a790a59b61b4434142398d4975-X'
    
    # Get available account sizes from database
    account_sizes = MT5Account.objects.filter(
        status='available', 
        assigned=False
    ).values_list('account_size', flat=True).distinct()
    
    context = {
        'public_key': public_key,
        'account_sizes': sorted(list(account_sizes))
    }
    
    return render(request, 'main/dashboard-purchase.html', context)

@csrf_exempt
def verify_payment(request):
    # Endpoint Flutterwave will call or client will POST tx_ref to verify
    if request.method != 'POST':
        return JsonResponse({'detail': 'Only POST allowed'}, status=405)

    # Parse JSON data if content type is application/json
    if request.content_type == 'application/json':
        try:
            data = json.loads(request.body)
            tx_ref = data.get('tx_ref')
            account_size = data.get('account_size')
        except json.JSONDecodeError:
            tx_ref = request.POST.get('tx_ref')
            account_size = request.POST.get('account_size')
    else:
        tx_ref = request.POST.get('tx_ref')
        account_size = request.POST.get('account_size')

    if not tx_ref:
        return JsonResponse({'detail': 'tx_ref required'}, status=400)

    # Verify with Flutterwave
    secret = settings.FLUTTERWAVE_SECRET_KEY or 'FLWSECK_TEST-732a1c10a2c6dbcff4fc8bf7da4942a3-X'
    headers = {'Authorization': f'Bearer {secret}'}
    resp = requests.get(f'https://api.flutterwave.com/v3/transactions/{tx_ref}/verify', headers=headers)
    
    if resp.status_code != 200:
        return JsonResponse({'detail': 'verification failed', 'resp': resp.text}, status=400)

    data = resp.json()
    if data.get('status') == 'success' and data.get('data', {}).get('status') == 'successful':
        # Mark purchase verified
        amount = data['data'].get('amount')
        customer = data['data'].get('customer', {})
        email = customer.get('email')

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return JsonResponse({'detail': 'user not found for payment email'}, status=404)

        # Create purchase record
        purchase_obj = Purchase.objects.create(
            user=user,
            tx_ref=tx_ref,
            amount=amount,
            verified=True,
            payment_status='successful',
            flutterwave_reference=data['data'].get('flw_ref')
        )

        # Get available MT5 account from CSV
        account_data = get_available_mt5_account(account_size)
        if not account_data:
            return JsonResponse({'detail': 'No available accounts found'}, status=400)

        # Create or update MT5Account in database
        try:
            mt5_account = MT5Account.objects.get(login=account_data['login'])
        except MT5Account.DoesNotExist:
            mt5_account = MT5Account(
                login=account_data['login'],
                password=account_data['password'],
                server=account_data['server'],
                account_size=account_data['account_size']
            )
        # Assign account to user
        mt5_account.assign_to_user(user)        
        # Link purchase to account
        purchase_obj.account = mt5_account
        purchase_obj.save()
        
        # Mark account as used in CSV
        mark_account_as_used(account_data['login'])

        messages.success(request._request, 'Payment successful! Your trading account has been assigned.')
        return JsonResponse({'detail': 'payment verified and account assigned', 'account': {
            'login': mt5_account.login,
            'password': mt5_account.password,
            'server': mt5_account.server,
            'account_size': mt5_account.account_size
        }})

    return JsonResponse({'detail': 'payment not successful', 'data': data}, status=400)

@login_required(login_url='/login_user')
def dashboard_accounts(request):
    logger.info("--- ENTERING dashboard_accounts ---")
    user_accounts = MT5Account.objects.filter(user=request.user, assigned=True).order_by('-assigned_date', '-id')
    # Refresh metrics for display on accounts page
    accounts_list = []
    if user_accounts.exists():
        try:
            accounts_list = myfxbook_fetch_accounts_with_retry()
        except Exception as e:
            logger.exception('Error fetching MyFXBook accounts list: %s', e)
            messages.error(request, f"Error fetching MyFXBook accounts: {str(e)}")
            accounts_list = []
        for account in user_accounts:
            try:
                update_account_data_from_myfxbook(account, accounts=accounts_list)
            except Exception as e:
                logger.exception('Error fetching MyFXBook data in accounts for login %s: %s', account.login, e)
                messages.error(request, f"Error fetching account data: {str(e)}")
            try:
                from decimal import Decimal
                initial = account.initial_balance or Decimal('0')
                target = (initial * Decimal('0.10')) if initial else Decimal('0')
                profit = account.profit or Decimal('0')
                progress = Decimal('0')
                if target > 0:
                    progress = (profit / target) * Decimal('100')
                if progress < 0:
                    progress = Decimal('0')
                elif progress > 100:
                    progress = Decimal('100')
                account.profit_percentage = float(progress)
            except Exception:
                account.profit_percentage = 0.0
    return render(request, 'main/dashboard-accounts.html', {'user_accounts': user_accounts})


@login_required(login_url='/login_user')
def dashboard_next_phase(request):
    user_accounts = MT5Account.objects.filter(user=request.user)
    
    if request.method == 'POST':
        request_type = request.POST.get('request_type')
        account_id = request.POST.get('account_id')
        
        if not account_id:
            messages.error(request, 'Please select an account')
            return redirect('dashboard_next_phase')
        
        try:
            account = MT5Account.objects.get(id=account_id, user=request.user)
        except MT5Account.DoesNotExist:
            messages.error(request, 'Invalid account selected')
            return redirect('dashboard_next_phase')
        
        # Create prop request
        prop_request = RealPropRequest.objects.create(
            user=request.user,
            request_type=request_type,
            mt5_account=account
        )
        
        messages.success(request, f'Your {request_type} request has been submitted and is pending approval')
        return redirect('dashboard_next_phase')
    
    # Get existing requests
    prop_requests = RealPropRequest.objects.filter(user=request.user).order_by('-created_at')
    
    return render(request, 'main/dashboard-next-phase.html', {
        'user_accounts': user_accounts,
        'prop_requests': prop_requests
    })


@login_required(login_url='/login_user')
def dashboard_rules(request):
    return render(request, 'main/dashboard-rules.html')


@login_required(login_url='/login_user')
def dashboard_referral(request):
    return render(request, 'main/dashboard-referral.html')


@login_required(login_url='/login_user')
def dashboard_payouts(request):
    # Only allow payouts from funded/real accounts (active status)
    eligible_accounts = MT5Account.objects.filter(user=request.user, status='active')
    
    if request.method == 'POST':
        account_id = request.POST.get('account_id')
        amount = request.POST.get('amount')
        payment_method = request.POST.get('payment_method')
        
        if not all([account_id, amount, payment_method]):
            messages.error(request, 'Please fill all required fields')
            return redirect('dashboard_payouts')
        
        try:
            # Enforce selection of an active (funded) account only
            account = MT5Account.objects.get(id=account_id, user=request.user, status='active')
            
            # Create payout request
            payout = Payout.objects.create(
                user=request.user,
                amount=amount,
                mt5_account=account,
                payment_method=payment_method
            )
            
            # Create prop request for payout (for admin tracking)
            RealPropRequest.objects.create(
                user=request.user,
                request_type='payout',
                mt5_account=account
            )
            
            messages.success(request, 'Your payout request has been submitted and is pending approval')
        except MT5Account.DoesNotExist:
            messages.error(request, 'Invalid account selected or account not eligible for payout')
        except Exception as e:
            messages.error(request, f'Error processing request: {str(e)}')
        
        return redirect('dashboard_payouts')
    
    # Get existing payouts
    payouts = Payout.objects.filter(user=request.user).order_by('-created_at')
    
    return render(request, 'main/dashboard-payouts.html', {
        'accounts': eligible_accounts,
        'payouts': payouts
    })


@login_required(login_url='/login_user')
def dashboard_transactions(request):
    purchases = Purchase.objects.filter(user=request.user).order_by('-created_at')
    return render(request, 'main/dashboard-transactions.html', {'purchases': purchases})


@login_required(login_url='/login_user')
def dashboard_certificates(request):
    certificates = Certificate.objects.filter(user=request.user).order_by('-issued_at')
    return render(request, 'main/dashboard-certificates.html', {
        'certificates': certificates,
    })

@login_required(login_url='/login_user')
def process_purchase(request):
    if request.method == 'POST':
        account_size = request.POST.get('account_size')
        amount = request.POST.get('amount')
        currency = 'NGN'

        if not account_size or not amount:
            messages.error(request, 'Please select an account size and enter amount.')
            return redirect('dashboard_purchase')

        tx_ref = f"txn-{uuid.uuid4().hex[:10]}"

        Purchase.objects.create(
            user=request.user,
            tx_ref=tx_ref,
            amount=amount,
            payment_status='pending',
            verified=False,
        )

        redirect_url = request.build_absolute_uri(reverse('payment_callback'))

        # Render checkout page for Flutterwave Inline
        public_key = settings.FLUTTERWAVE_PUBLIC_KEY or 'FLWPUBK_TEST-bcdf22a790a59b61b4434142398d4975-X'
        context = {
            'public_key': public_key,
            'tx_ref': tx_ref,
            'amount': amount,
            'currency': currency,
            'account_size': account_size,
            'redirect_url': redirect_url,
        }
        return render(request, 'main/payment-checkout.html', context)

    return redirect('dashboard_purchase')

@csrf_exempt
@require_http_methods(["GET", "POST"])
def payment_callback(request):
    if request.method == "POST":
        try:
            webhook_data = json.loads(request.body.decode('utf-8'))
            event_type = webhook_data.get('event')
            transaction_data = webhook_data.get('data', {})
            tx_ref = transaction_data.get('tx_ref')
            transaction_id = transaction_data.get('id')
            status = transaction_data.get('status')

            try:
                purchase = Purchase.objects.get(tx_ref=tx_ref)
            except Purchase.DoesNotExist:
                return HttpResponse(status=404)

            if event_type == 'charge.completed' and status in ['successful', 'completed']:
                verification_response = verify_transaction(transaction_id)
                if (verification_response.get('status') == 'success' and 
                    verification_response.get('data', {}).get('status') in ['successful', 'completed']):
                    amount = verification_response['data'].get('amount')
                    currency = verification_response['data'].get('currency')
                    customer = verification_response['data'].get('customer', {})
                    email = customer.get('email')
                    meta = verification_response['data'].get('meta', {})
                    account_size = meta.get('account_size')

                    from decimal import Decimal
                    if Decimal(str(amount)) == Decimal(str(purchase.amount)) and currency == 'NGN':
                        # Resolve user
                        try:
                            user = CustomUser.objects.get(email=email)
                        except CustomUser.DoesNotExist:
                            user = purchase.user

                        purchase.flutterwave_reference = verification_response['data'].get('flw_ref')
                        purchase.payment_status = 'successful'
                        purchase.verified = True
                        purchase.save()

                        # Get available MT5 account
                        account_data = get_available_mt5_account(account_size)
                        if account_data:
                            try:
                                mt5_account = MT5Account.objects.get(login=account_data['login'])
                                mt5_account.assign_to_user(user)
                                purchase.account = mt5_account
                                purchase.save()
                                messages.success(request._request, 'Payment successful! Your trading account has been assigned.')
                            except MT5Account.DoesNotExist:
                                messages.error(request._request, 'Error assigning account. Please contact support.')
                        else:
                            normalized_size = normalize_account_size(account_size)
                            messages.error(request._request, f'No available {normalized_size or account_size} accounts found. Please contact support.')
                        return HttpResponse(status=200)
            elif status == 'failed':
                purchase.payment_status = 'failed'
                purchase.save()
                return HttpResponse(status=200)
        except Exception as e:
            print(f"Webhook error: {str(e)}")
            return HttpResponse(status=400)

    elif request.method == "GET":
        status = request.GET.get('status')
        tx_ref = request.GET.get('tx_ref')
        transaction_id = request.GET.get('transaction_id')

        try:
            purchase = Purchase.objects.get(tx_ref=tx_ref)
        except Purchase.DoesNotExist:
            messages.error(request, "Transaction not found.")
            return redirect('dashboard_purchase')

        if status in ['successful', 'completed']:
            # Try verify by transaction_id first if available, else by reference
            verification_response = verify_transaction(transaction_id) if transaction_id else verify_transaction_by_reference(tx_ref)
            # Fallback: if verification by id fails, try by reference
            if not (
                verification_response.get('status') == 'success' and 
                verification_response.get('data', {}).get('status') in ['successful', 'completed']
            ) and transaction_id:
                verification_response = verify_transaction_by_reference(tx_ref)

            if (
                verification_response.get('status') == 'success' and 
                verification_response.get('data', {}).get('status') in ['successful', 'completed']
            ):
                amount = verification_response['data'].get('amount')
                currency = verification_response['data'].get('currency')
                meta = verification_response['data'].get('meta', {})
                account_size = meta.get('account_size')

                from decimal import Decimal
                if Decimal(str(amount)) == Decimal(str(purchase.amount)) and currency == 'NGN':
                    purchase.flutterwave_reference = verification_response['data'].get('flw_ref')
                    purchase.payment_status = 'successful'
                    purchase.verified = True
                    purchase.save()

                    # Assign MT5 account to current user
                    user = request.user if request.user.is_authenticated else purchase.user
                    account_data = get_available_mt5_account(account_size)
                    if account_data:
                        try:
                            mt5_account = MT5Account.objects.get(login=account_data['login'])
                            mt5_account.assign_to_user(user)
                            purchase.account = mt5_account
                            purchase.save()
                            messages.success(request, 'Payment successful! Your trading account has been assigned.')
                            return redirect('dashboard_accounts')
                        except MT5Account.DoesNotExist:
                            messages.error(request, 'Error assigning account. Please contact support.')
                            return redirect('dashboard_purchase')
                    else:
                        normalized_size = normalize_account_size(account_size)
                        messages.error(request, f'No available {normalized_size or account_size} accounts found. Please contact support.')
                        return redirect('dashboard_purchase')
                else:
                    messages.error(request, 'Payment verification failed.')
            else:
                messages.error(request, 'Payment verification failed.')
        elif status == 'cancelled':
            purchase.payment_status = 'failed'
            purchase.save()
            messages.error(request, "Payment was cancelled.")
        else:
            messages.error(request, f"Payment failed with status: {status}. Please try again.")

        return redirect('dashboard_purchase')


def verify_transaction(transaction_id):
    try:
        if not transaction_id:
            return {'status': 'error', 'data': {}, 'message': 'Missing transaction_id'}
        url = f"https://api.flutterwave.com/v3/transactions/{transaction_id}/verify"
        headers = {
            'Authorization': f"Bearer {getattr(settings, 'FLUTTERWAVE_SECRET_KEY', 'FLWSECK_TEST-732a1c10a2c6dbcff4fc8bf7da4942a3-X')}",
            'Content-Type': 'application/json',
        }
        response = requests.get(url, headers=headers, timeout=10)
        return response.json()
    except requests.exceptions.Timeout:
        return {'status': 'error', 'data': {}, 'message': 'Verification timeout'}
    except requests.exceptions.ConnectionError as e:
        return {'status': 'error', 'data': {}, 'message': f'Connection error: {str(e)}'}
    except Exception as e:
        return {'status': 'error', 'data': {}, 'message': f'Unexpected error: {str(e)}'}


def verify_transaction_by_reference(tx_ref):
    try:
        if not tx_ref:
            return {'status': 'error', 'data': {}, 'message': 'Missing tx_ref'}
        url = f"https://api.flutterwave.com/v3/transactions/verify_by_reference?tx_ref={tx_ref}"
        headers = {
            'Authorization': f"Bearer {getattr(settings, 'FLUTTERWAVE_SECRET_KEY', 'FLWSECK_TEST-732a1c10a2c6dbcff4fc8bf7da4942a3-X')}",
            'Content-Type': 'application/json',
        }
        response = requests.get(url, headers=headers, timeout=10)
        return response.json()
    except requests.exceptions.Timeout:
        return {'status': 'error', 'data': {}, 'message': 'Verification timeout'}
    except requests.exceptions.ConnectionError as e:
        return {'status': 'error', 'data': {}, 'message': f'Connection error: {str(e)}'}
    except Exception as e:
        return {'status': 'error', 'data': {}, 'message': f'Unexpected error: {str(e)}'}


