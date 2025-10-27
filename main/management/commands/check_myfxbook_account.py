from django.core.management.base import BaseCommand, CommandError

from main.views import myfxbook_fetch_accounts_with_retry


def _server_matches(acc_server, server):
    """Return True if server matches, considering brand names like 'EXNESS' vs 'Exness-MT5Trial9'."""
    if server is None:
        return True
    if acc_server is None:
        return False
    as_norm = str(acc_server).strip().lower()
    s_norm = server.strip().lower()
    if as_norm == s_norm:
        return True
    brand = s_norm.split('-', 1)[0]
    return as_norm == brand

class Command(BaseCommand):
    help = "Check MyFXBook for a specific MT5 login and optional server; prints matched account info."

    def add_arguments(self, parser):
        parser.add_argument('--login', required=True, help='MT5 login number, e.g., 211578896')
        parser.add_argument('--server', required=False, help='Broker server name, e.g., Exness-MT5Trial9')
        parser.add_argument('--print-json', action='store_true', help='Print full matched account JSON')
        parser.add_argument('--print-accounts', action='store_true', help='Print all accounts (login/server)')

    def handle(self, *args, **options):
        login = str(options['login']).strip()
        server = options.get('server')
        if server:
            server = server.strip()
        try:
            accounts = myfxbook_fetch_accounts_with_retry()
        except Exception as e:
            raise CommandError(f"Failed to fetch MyFXBook accounts: {e}")

        if not accounts:
            raise CommandError("No MyFXBook accounts returned by API.")

        if options.get('print_accounts'):
            for i, acc in enumerate(accounts, 1):
                acc_id = acc.get('accountId') or acc.get('id')
                acc_login = acc.get('login')
                acc_server_raw = acc.get('server')
                if isinstance(acc_server_raw, dict):
                    acc_server = acc_server_raw.get('server') or acc_server_raw.get('name') or None
                else:
                    acc_server = acc_server_raw
                self.stdout.write(f"{i}. accountId={acc_id} login={acc_login} server={acc_server}")
            return

        matched = None
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

            # Prefer accountId exact match
            try:
                if acc_id is not None and str(acc_id).strip() == login:
                    if _server_matches(acc_server, server):
                        matched = acc
                        break
            except Exception:
                pass
            # Fallback: login field match
            if acc_login is not None and str(acc_login).strip() == login:
                if _server_matches(acc_server, server):
                    matched = acc
                    break

        if not matched:
            raise CommandError(f"No matching MyFXBook account found for login {login}{' on server ' + server if server else ''}.")

        if options['print_json']:
            import json
            self.stdout.write(json.dumps(matched, indent=2))
        else:
            fields = {
                'accountId': matched.get('accountId'),
                'login': matched.get('login'),
                'server': matched.get('server'),
                'name': matched.get('name'),
                'balance': matched.get('balance'),
                'equity': matched.get('equity'),
                'profit': matched.get('profit'),
                'drawdown': matched.get('drawdown'),
            }
            for k, v in fields.items():
                self.stdout.write(f"{k}: {v}")
            self.stdout.write(self.style.SUCCESS("Matched MyFXBook account successfully."))