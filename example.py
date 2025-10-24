
@login_required(login_url='/login_user')
def checkout(request):
    categories = Category.objects.all()
    cart = None
    cart_items = []
    subtotal = 0
    total_price = 0
    address = None
    applied_discount = None
    discount_amount = 0

    try:
        cart = Cart.objects.get(user=request.user)
        cart_items = cart.items.all()
        subtotal = sum(item.total_price() for item in cart_items)
        
        # Check for applied discount code in session
        if request.session.get('discount_code'):
            try:
                from decimal import Decimal
                subscriber = EmailSubscriber.objects.get(
                    discount_code=request.session['discount_code'],
                    code_used=False,
                    is_active=True
                )
                stored_cart_total = Decimal(str(request.session.get('cart_total', '0')))
                
                # Verify the cart total hasn't changed significantly
                if abs(stored_cart_total - subtotal) < Decimal('1'):  # Allow for minor rounding differences
                    if subtotal >= 150000:
                        stored_discount = request.session.get('discount_amount', '0')
                        discount_amount = Decimal(str(stored_discount))
                        applied_discount = subscriber
                        total_price = subtotal - discount_amount
                    else:
                        # Clear discount if cart total drops below threshold
                        request.session.pop('discount_code', None)
                        request.session.pop('cart_total', None)
                        request.session.pop('discount_amount', None)
                        total_price = subtotal
                else:
                    # Cart total has changed significantly, clear discount
                    request.session.pop('discount_code', None)
                    request.session.pop('cart_total', None)
                    request.session.pop('discount_amount', None)
                    total_price = subtotal
            except EmailSubscriber.DoesNotExist:
                # Clear invalid discount code
                request.session.pop('discount_code', None)
                request.session.pop('cart_total', None)
                request.session.pop('discount_amount', None)
                total_price = subtotal
        else:
            total_price = subtotal
            
        address = request.user.address if hasattr(request.user, 'address') and request.user.address else None
    except Cart.DoesNotExist:
        messages.error(request, "Your cart is empty.")
        return redirect('cart')

    if not cart_items:
        messages.error(request, "Your cart is empty.")
        return redirect('cart')

    if request.method == 'POST':
        form = CheckoutForm(request.POST, instance=address)
        if form.is_valid():
            address = form.save()
            if not request.user.address:
                request.user.address = address
                request.user.save()
            messages.success(request, "Delivery address updated successfully.")
            # Create a transaction before redirecting to Flutterwave
            tx_ref = f"txn-{uuid.uuid4().hex[:10]}"  # Generate unique transaction reference
            transaction = Transaction.objects.create(
                user=request.user,
                amount=total_price,
                tx_ref=tx_ref,
                address=address,
                transaction_status='pending'
            )
            # Add products to the transaction
            transaction.products.set([item.product for item in cart_items])
            transaction.save()
            # Redirect to Flutterwave payment (handled in template)
            return redirect('initiate_payment', transaction_id=transaction.id)
        else:
            messages.error(request, "Please correct the errors in the form.")
    else:
        form = CheckoutForm(instance=address)

    context = {
        'cart': cart,
        'cart_items': cart_items,
        'subtotal': subtotal,
        'total_price': total_price,
        'form': form,
        'categories': categories,
        'applied_discount': applied_discount,
        'discount_amount': discount_amount,
    }
    return render(request, 'SuxesApp/checkout.html', context)

@login_required(login_url='/login_user')
def initiate_payment(request, transaction_id):
    transaction = get_object_or_404(Transaction, id=transaction_id, user=request.user)
    cart = Cart.objects.get(user=request.user)
    cart_items = cart.items.all()

    context = {
        'transaction': transaction,
        'cart_items': cart_items,
        'public_key': settings.FLUTTERWAVE_PUBLIC_KEY,
        'redirect_url': 'https://www.suxesluxthread.com/payment-callback',
        'customer': {
            'name': f"{request.user.first_name} {request.user.last_name}",
            'email': request.user.email,
        },
    }
    return render(request, 'SuxesApp/initiate_payment.html', context)

import json
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

# views.py
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
                transaction = Transaction.objects.get(tx_ref=tx_ref)
            except Transaction.DoesNotExist:
                return HttpResponse(status=404)

            if event_type == 'charge.completed' and status in ['successful', 'completed']:
                verification_response = verify_transaction(transaction_id)
                if (verification_response['status'] == 'success' and 
                    verification_response['data']['status'] in ['successful', 'completed'] and
                    verification_response['data']['amount'] == float(transaction.amount) and
                    verification_response['data']['currency'] == 'NGN'):
                    transaction.flw_transaction_id = transaction_id
                    transaction.transaction_status = 'processing'
                    transaction.save()
                    cart = Cart.objects.get(user=transaction.user)
                    cart_items = cart.items.all()
                    for cart_item in cart_items:
                        product = cart_item.product
                        if product.in_stock >= cart_item.quantity:
                            product.in_stock -= cart_item.quantity
                            product.save()
                        else:
                            transaction.transaction_status = 'declined'
                            transaction.save()
                            return HttpResponse(status=400)
                    cart_items.delete()
            elif status == 'failed':
                transaction.transaction_status = 'declined'
                transaction.save()
            return HttpResponse(status=200)
        except Exception as e:
            print(f"Webhook error: {str(e)}")
            return HttpResponse(status=400)

    elif request.method == "GET":
        status = request.GET.get('status')
        tx_ref = request.GET.get('tx_ref')
        transaction_id = request.GET.get('transaction_id')

        if status in ['successful', 'completed']:
            try:
                transaction = Transaction.objects.get(tx_ref=tx_ref)
                verification_response = verify_transaction(transaction_id)
                if (verification_response['status'] == 'success' and 
                    verification_response['data']['status'] in ['successful', 'completed'] and
                    verification_response['data']['amount'] == float(transaction.amount) and
                    verification_response['data']['currency'] == 'NGN'):
                    transaction.flw_transaction_id = transaction_id
                    transaction.transaction_status = 'processing'
                    transaction.save()
                    cart = Cart.objects.get(user=transaction.user)
                    cart_items = cart.items.all()
                    for cart_item in cart_items:
                        product = cart_item.product
                        if product.in_stock >= cart_item.quantity:
                            product.in_stock -= cart_item.quantity
                            product.save()
                        else:
                            transaction.transaction_status = 'declined'
                            transaction.save()
                            messages.error(request, f"Insufficient stock for {product.name}.")
                            return redirect('cart')
                    cart_items.delete()
                    messages.success(request, "Payment successful! Your order is being processed.")
                    return redirect('thank_you', transaction_id=transaction.id)  # Redirect to thank_you page
                else:
                    print(f"Verification failed: {verification_response}")
                    transaction.transaction_status = 'declined'
                    transaction.save()
                    messages.error(request, "Payment verification failed.")
            except Transaction.DoesNotExist:
                messages.error(request, "Transaction not found.")
        elif status == 'cancelled':
            try:
                transaction = Transaction.objects.get(tx_ref=tx_ref)
                transaction.transaction_status = 'declined'
                transaction.save()
                messages.error(request, "Payment was cancelled.")
            except Transaction.DoesNotExist:
                messages.error(request, "Transaction not found.")
        else:
            messages.error(request, f"Payment failed with status: {status}. Please try again.")

        return redirect('cart')

def thank_you(request, transaction_id):
    transaction = get_object_or_404(Transaction, id=transaction_id, user=request.user)
    categories = Category.objects.all()
    cart_count = Cart.objects.get(user=request.user).items.count() if request.user.is_authenticated else 0

    context = {
        'transaction': transaction,
        'categories': categories,
        'cart_count': cart_count,
    }
    return render(request, 'SuxesApp/thank_you.html', context)



def verify_transaction(transaction_id):
    url = f"https://api.flutterwave.com/v3/transactions/{transaction_id}/verify"
    headers = {
        'Authorization': f'Bearer {settings.FLUTTERWAVE_SECRET_KEY}',
        'Content-Type': 'application/json',
    }
    response = requests.get(url, headers=headers)
    return response.json()