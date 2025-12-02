"""
Factory Boy factories for creating test data
Makes it easy to create users, profiles, and other models for testing
"""
import factory
from factory.django import DjangoModelFactory
from faker import Faker
from django.contrib.auth import get_user_model

fake = Faker()
User = get_user_model()


class UserFactory(DjangoModelFactory):
    """Factory for creating User instances in tests."""

    class Meta:
        model = User
        django_get_or_create = ('email',)

    email = factory.Sequence(lambda n: f'user{n}@capaciti.org.za')
    first_name = factory.Faker('first_name')
    last_name = factory.Faker('last_name')
    role = 'candidate'
    is_active = True
    is_staff = False

    @factory.post_generation
    def password(self, create, extracted, **kwargs):
        """Set password after user creation."""
        if not create:
            return

        if extracted:
            self.set_password(extracted)
        else:
            # Default strong password for tests
            self.set_password('TestPass123!')


class AdminUserFactory(UserFactory):
    """Factory for creating Admin users."""

    role = 'admin'
    is_staff = True
    email = factory.Sequence(lambda n: f'admin{n}@capaciti.org.za')


class SuperuserFactory(UserFactory):
    """Factory for creating Superuser accounts."""

    role = 'superuser'
    is_staff = True
    is_superuser = True
    email = factory.Sequence(lambda n: f'superuser{n}@capaciti.org.za')


class UserProfileFactory(DjangoModelFactory):
    """Factory for creating UserProfile instances."""

    class Meta:
        model = 'users.UserProfile'

    user = factory.SubFactory(UserFactory)
    contact_number = factory.Faker('phone_number')
    address = factory.Faker('address')

    # SA ID number format: YYMMDDGSSSCAZ
    id_number = factory.LazyAttribute(lambda o: fake.numerify(text='##########0##'))

    # Emergency contact
    emergency_contact = factory.Faker('name')
    emergency_phone = factory.Faker('phone_number')

    # Medical info (optional)
    diagnosis = factory.Maybe(
        'with_medical',
        yes_declaration=factory.Faker('sentence'),
        no_declaration=None
    )
    medications = factory.Maybe(
        'with_medical',
        yes_declaration=factory.Faker('sentence'),
        no_declaration=None
    )
    allergies = factory.Maybe(
        'with_medical',
        yes_declaration=factory.Faker('sentence'),
        no_declaration=None
    )

    class Params:
        with_medical = factory.Trait()


class PasswordHistoryFactory(DjangoModelFactory):
    """Factory for creating PasswordHistory instances."""

    class Meta:
        model = 'users.PasswordHistory'

    user = factory.SubFactory(UserFactory)
    password_hash = factory.LazyAttribute(
        lambda o: User().set_password('OldPassword123!')  # Create a hash
    )
