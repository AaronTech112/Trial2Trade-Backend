from django.core.management.base import BaseCommand
import csv
from main.models import MT5Account

class Command(BaseCommand):
    help = 'Import MT5 accounts from a CSV file (login,password,server)'

    def add_arguments(self, parser):
        parser.add_argument('csvfile', type=str, help='Path to CSV file')

    def handle(self, *args, **options):
        path = options['csvfile']
        count = 0
        with open(path, newline='') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if not row: continue
                login = row[0].strip()
                password = row[1].strip() if len(row) > 1 else ''
                server = row[2].strip() if len(row) > 2 else ''
                if MT5Account.objects.filter(login=login).exists():
                    continue
                MT5Account.objects.create(login=login, password=password, server=server)
                count += 1
        self.stdout.write(self.style.SUCCESS(f'Imported {count} MT5 accounts'))
