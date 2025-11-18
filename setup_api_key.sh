#!/bin/bash
# Setup script for Anthropic API key

echo "============================================"
echo "  SOC AI Dashboard - API Key Setup"
echo "============================================"
echo ""
echo "To use Claude AI for intelligent alert analysis, you need an Anthropic API key."
echo ""
echo "📝 How to get your API key:"
echo "   1. Visit: https://console.anthropic.com/"
echo "   2. Sign up or log in"
echo "   3. Go to 'API Keys' section"
echo "   4. Create a new API key"
echo ""
echo "⚠️  Keep your API key secure - do not share it publicly!"
echo ""

# Prompt for API key
read -p "Enter your Anthropic API key (or press Enter to skip): " api_key

if [ -z "$api_key" ]; then
    echo ""
    echo "⏭️  Skipped. You can set it later with:"
    echo "   export ANTHROPIC_API_KEY='your-key-here'"
    echo ""
else
    # Set environment variable
    export ANTHROPIC_API_KEY="$api_key"

    # Add to ~/.bashrc for persistence
    if ! grep -q "ANTHROPIC_API_KEY" ~/.bashrc; then
        echo "" >> ~/.bashrc
        echo "# Anthropic API Key for SOC Dashboard" >> ~/.bashrc
        echo "export ANTHROPIC_API_KEY='$api_key'" >> ~/.bashrc
        echo "✅ Added to ~/.bashrc for persistence"
    fi

    echo ""
    echo "✅ API key set successfully!"
    echo ""
fi

echo "============================================"
echo "  Next Steps:"
echo "============================================"
echo "1. Restart the backend server:"
echo "   cd /home/user/SOC"
echo "   pkill -f uvicorn"
echo "   uvicorn lg_sotf.api.app:app --host 0.0.0.0 --port 8000 --reload"
echo ""
echo "2. Access the dashboard at: http://localhost:3001"
echo ""
echo "3. Monitor logs:"
echo "   tail -f /tmp/backend.log"
echo "============================================"
