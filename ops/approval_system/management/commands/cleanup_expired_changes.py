from django.core.management.base import BaseCommand
from ops.approval_system.services import ApprovalService


class Command(BaseCommand):
    help = 'Cleanup expired pending changes'

    def handle(self, *args, **options):
        count = ApprovalService.cleanup_expired_changes()
        self.stdout.write(
            self.style.SUCCESS(f'Successfully cleaned up {count} expired changes')
        )
