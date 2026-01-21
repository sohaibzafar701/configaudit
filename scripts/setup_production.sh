#!/bin/bash
# Production setup script for NCRT
# This script helps set up the application for production deployment

set -e

echo "=== NCRT Production Setup ==="
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "Creating .env file from .env.example..."
    cp .env.example .env
    echo "✓ .env file created"
else
    echo "✓ .env file already exists"
fi

# Generate secret key if not set or is default
if grep -q "django-insecure-ncrt-dev-key-change-in-production" .env || grep -q "your-secret-key-here-change-in-production" .env; then
    echo ""
    echo "Generating new secret key..."
    if command -v python3 &> /dev/null; then
        SECRET_KEY=$(python3 scripts/generate_secret_key.py 2>/dev/null | grep "SECRET_KEY=" | cut -d'=' -f2)
        if [ -n "$SECRET_KEY" ]; then
            # Update .env file with new secret key
            if [[ "$OSTYPE" == "darwin"* ]]; then
                # macOS
                sed -i '' "s|SECRET_KEY=.*|SECRET_KEY=$SECRET_KEY|" .env
            else
                # Linux
                sed -i "s|SECRET_KEY=.*|SECRET_KEY=$SECRET_KEY|" .env
            fi
            echo "✓ Secret key generated and updated in .env"
        else
            echo "⚠ Could not generate secret key automatically. Please run:"
            echo "   python3 scripts/generate_secret_key.py"
            echo "   Then update SECRET_KEY in .env file"
        fi
    else
        echo "⚠ Python3 not found. Please generate secret key manually:"
        echo "   python3 scripts/generate_secret_key.py"
    fi
else
    echo "✓ Secret key already set"
fi

# Create necessary directories
echo ""
echo "Creating necessary directories..."
mkdir -p data
mkdir -p logs
mkdir -p media
mkdir -p staticfiles
echo "✓ Directories created"

# Set permissions
echo ""
echo "Setting file permissions..."
chmod 600 .env 2>/dev/null || true
echo "✓ .env file permissions set (read/write for owner only)"

# Check if virtual environment exists
if [ ! -d "venv" ] && [ ! -d "env" ]; then
    echo ""
    echo "⚠ No virtual environment found. Consider creating one:"
    echo "   python3 -m venv venv"
    echo "   source venv/bin/activate"
    echo "   pip install -r requirements.txt"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "1. Review and update .env file with your production settings"
echo "2. If using PostgreSQL, update DATABASE_* settings in .env"
echo "3. Set DEBUG=False in .env for production"
echo "4. Configure SSL/HTTPS and update security settings in .env"
echo "5. Run: python3 manage.py collectstatic"
echo "6. Run: python3 manage.py migrate"
echo "7. Start the application with gunicorn"
