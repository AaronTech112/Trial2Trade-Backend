from django.core.management.base import BaseCommand
import csv
from main.models import MT5Account

class Command(BaseCommand):
    help = 'Import MT5 accounts from CSV file'

    def add_arguments(self, parser):
        parser.add_argument('csv_file', type=str, help='Path to CSV file')

    def handle(self, *args, **options):
        csv_file = options['csv_file']
        imported = 0
        skipped = 0

        with open(csv_file, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                login = row['MT5 Login'].strip()
                
                # Skip if account already exists
                if MT5Account.objects.filter(login=login).exists():
                    skipped += 1
                    continue

                # Create new account
                MT5Account.objects.create(
                    login=login,
                    password=row['MT5 Password'].strip(),
                    server=row['MT5 Server'].strip(),
                    account_size=row['Account Size'].strip(),
                    status='available' if row['Status'].strip().lower() == 'available' else 'assigned'
                )
                imported += 1

        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully imported {imported} accounts ({skipped} skipped as already existing)'
            )
        )