# Payment Transactions

The backend now stores all payment transactions in the `payment_transactions` table.

## Database Schema

The `payment_transactions` table stores the following information:

- `payment_id`: Unique identifier for the payment transaction
- `user_id`: User who made the payment
- `stripe_session_id`: Stripe checkout session ID
- `stripe_payment_intent_id`: Stripe payment intent ID (if available)
- `package_id`: ID of the package purchased
- `package_name`: Name of the package (Starter, Professional, Enterprise)
- `tokens_purchased`: Number of tokens purchased
- `amount_paid`: Amount paid in USD
- `currency`: Currency code (default: 'usd')
- `payment_status`: Payment status (paid, pending, failed, etc.)
- `payment_method`: Payment method used (card, etc.)
- `customer_email`: Customer email address (if available)
- `created_at`: Timestamp of when the payment was processed

## How It Works

1. When a user completes a Stripe checkout, the webhook handler receives a `checkout.session.completed` event
2. The handler:
   - Retrieves payment details from Stripe
   - Adds credits to the user's balance
   - Stores the payment transaction in the database
   - Uses database transactions to ensure data consistency

## Querying Payment Transactions

### Get all payments for a user:
```sql
SELECT * FROM payment_transactions 
WHERE user_id = 'user_123' 
ORDER BY created_at DESC;
```

### Get total revenue:
```sql
SELECT SUM(amount_paid) as total_revenue 
FROM payment_transactions 
WHERE payment_status = 'paid';
```

### Get payments by package:
```sql
SELECT package_name, COUNT(*) as count, SUM(amount_paid) as revenue
FROM payment_transactions 
WHERE payment_status = 'paid'
GROUP BY package_name;
```

### Get recent payments:
```sql
SELECT pt.*, u.user_id 
FROM payment_transactions pt
JOIN users u ON pt.user_id = u.user_id
WHERE payment_status = 'paid'
ORDER BY created_at DESC
LIMIT 100;
```

## Notes

- All payment transactions are stored even if the payment fails (with appropriate status)
- The system uses database transactions to ensure credits are only added if the payment record is successfully created
- Payment intent details are retrieved from Stripe when available for additional payment information

