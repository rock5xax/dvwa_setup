#!/bin/bash

# Exit on error
set -e

# Check if user is root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run by the root user."
    exit 1
fi

# Function to check and install programs
check_program() {
    if ! dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; then
        echo "$1 is not installed. Installing now..."
        apt install -y "$1" || {
            echo "Failed to install $1."
            exit 1
        }
    else
        echo "$1 is installed!"
    fi
}

# Variables
DVWA_DIR="/var/www/html/DVWA"
DB_NAME="dvwa"
DB_USER="dvwa"
DB_PASSWORD="p@ssw0rd"
DB_HOST="localhost"
APACHE_USER="www-data"
RECAPTCHA_PUBLIC_KEY="YOUR_SITE_KEY" # Replace with your key
RECAPTCHA_PRIVATE_KEY="YOUR_SECRET_KEY" # Replace with your key
INPUT_URL="dvwatest.com"

# Display URL
echo "Using URL: $INPUT_URL"

# Warning
echo "WARNING: DVWA is vulnerable. Restrict port 80 to your IP."
read -p "Proceed? (y/N): " proceed
if [[ ! "$proceed" =~ ^[Yy]$ ]]; then
    echo "Setup aborted."
    exit 1
fi

# Update repositories
echo "Updating repositories..."
apt update

# Check and install dependencies
echo "Verifying and installing dependencies..."
check_program apache2
check_program mariadb-server
check_program mariadb-client
check_program php
check_program php-mysql
check_program php-gd
check_program libapache2-mod-php
check_program git
check_program composer

# Download DVWA
if [ -d "$DVWA_DIR" ]; then
    echo "Attention! DVWA folder already exists."
    read -p "Delete and re-download? (y/N): " response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        rm -rf "$DVWA_DIR"
        echo "Downloading DVWA from GitHub..."
        git clone https://github.com/digininja/DVWA.git "$DVWA_DIR"
    else
        echo "Continuing with existing DVWA folder."
    fi
else
    echo "Downloading DVWA from GitHub..."
    git clone https://github.com/digininja/DVWA.git "$DVWA_DIR"
fi

# Configure Apache and MariaDB services
for service in mariadb apache2; do
    if systemctl is-enabled "$service" &>/dev/null; then
        echo "$service is already enabled."
    else
        echo "Enabling $service..."
        systemctl enable "$service" &>/dev/null
    fi
    if systemctl is-active --quiet "$service"; then
        echo "$service is already running."
    else
        echo "Starting $service..."
        systemctl start "$service"
    fi
done

# Database setup with default root/no password
echo "Setting up database with default root credentials..."
mysql -u root <<EOF
CREATE DATABASE IF NOT EXISTS $DB_NAME;
CREATE USER IF NOT EXISTS '$DB_USER'@'$DB_HOST' IDENTIFIED BY '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'$DB_HOST';
FLUSH PRIVILEGES;
EOF
if [ $? -eq 0 ]; then
    echo "Database setup successful."
else
    echo "Database setup failed. Check MariaDB status."
    exit 1
fi

# Configure DVWA
echo "Configuring DVWA..."
CONFIG_FILE="$DVWA_DIR/config/config.inc.php"
cp "$DVWA_DIR/config/config.inc.php.dist" "$CONFIG_FILE"
sed -i "s/\$_DVWA\[ 'db_user' \] = '.*';/\$_DVWA[ 'db_user' ] = '$DB_USER';/" "$CONFIG_FILE"
sed -i "s/\$_DVWA\[ 'db_password' \] = '.*';/\$_DVWA[ 'db_password' ] = '$DB_PASSWORD';/" "$CONFIG_FILE"
sed -i "s/\$_DVWA\[ 'db_database' \] = '.*';/\$_DVWA[ 'db_database' ] = '$DB_NAME';/" "$CONFIG_FILE"
sed -i "s/\$_DVWA\[ 'db_server' \] = '.*';/\$_DVWA[ 'db_server' ] = '$DB_HOST';/" "$CONFIG_FILE"
sed -i "s/\$_DVWA\[ 'recaptcha_public_key' \] = '.*';/\$_DVWA[ 'recaptcha_public_key' ] = '$RECAPTCHA_PUBLIC_KEY';/" "$CONFIG_FILE"
sed -i "s/\$_DVWA\[ 'recaptcha_private_key' \] = '.*';/\$_DVWA[ 'recaptcha_private_key' ] = '$RECAPTCHA_PRIVATE_KEY';/" "$CONFIG_FILE"
chown "$APACHE_USER:$APACHE_USER" "$CONFIG_FILE"
chmod 644 "$CONFIG_FILE"

# Set permissions
echo "Setting permissions..."
chown -R "$APACHE_USER:$APACHE_USER" "$DVWA_DIR"
chmod -R 755 "$DVWA_DIR"
mkdir -p "$DVWA_DIR/hackable/uploads"
chown "$APACHE_USER:$APACHE_USER" "$DVWA_DIR/hackable/uploads"
chmod 777 "$DVWA_DIR/hackable/uploads"

# Configure PHP
echo "Configuring PHP..."
PHP_INI="/etc/php/$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')/apache2/php.ini"
if [ -f "$PHP_INI" ]; then
    sed -i 's/^\(allow_url_include =\).*/\1 On/' "$PHP_INI"
    sed -i 's/^\(allow_url_fopen =\).*/\1 On/' "$PHP_INI"
    sed -i 's/^\(display_errors =\).*/\1 On/' "$PHP_INI"
    sed -i 's/^\(display_startup_errors =\).*/\1 On/' "$PHP_INI"
else
    echo "Warning: PHP config file not found."
fi

# Install API vendor files (skip if no composer.json)
echo "Installing API vendor files..."
cd "$DVWA_DIR"
if [ -f "composer.json" ]; then
    composer install --no-dev || {
        echo "Warning: Composer install failed. API module may not work."
    }
    chown -R "$APACHE_USER:$APACHE_USER" "$DVWA_DIR/vendor"
else
    echo "No composer.json found. Skipping Composer install."
fi

# Configure Apache redirect
echo "Configuring Apache redirect..."
APACHE_CONF="/etc/apache2/sites-available/000-default.conf"
if ! grep -q "RedirectMatch ^/$ /DVWA/login.php" "$APACHE_CONF"; then
    sed -i '/<VirtualHost \*:80>/,/<\/VirtualHost>/ s/DocumentRoot \/var\/www\/html/&\n        RedirectMatch ^\/$ \/DVWA\/login.php/' "$APACHE_CONF"
fi
a2enmod rewrite
sed -i '/<VirtualHost \*:80>/,/<\/VirtualHost>/ s/<Directory \/var\/www\/>/&\n        AllowOverride All/' "$APACHE_CONF"

# Restart Apache with delay to avoid start-limit-hit
echo "Restarting Apache..."
systemctl stop apache2 &>/dev/null || true
sleep 2 # Delay to prevent start-limit-hit
systemctl start apache2 || {
    echo "Failed to restart Apache. Check logs: /var/log/apache2/error.log"
    exit 1
}

# Initialize DVWA database
echo "Initializing DVWA database..."
curl -s -o /dev/null "http://localhost/DVWA/setup.php?action=install" || {
    echo "Automatic database init failed. Visit http://$INPUT_URL/DVWA/setup.php and click 'Create / Reset Database'."
}

# Test setup
echo "Testing DVWA..."
curl -s -o /dev/null -w "%{http_code}" http://localhost/DVWA/login.php | grep -q 200 || {
    echo "DVWA test failed. Check /var/log/apache2/error.log."
    exit 1
}
curl -s -o /dev/null -w "%{http_code}" http://localhost/ | grep -q 302 || {
    echo "Redirect test failed. Check Apache config."
    exit 1
}

# Final message
echo "DVWA installed successfully!"
echo "Access: http://$INPUT_URL/ (redirects to DVWA)"
echo "Credentials:"
echo "Username: admin"
echo "Password: password"
echo "Restrict port 80: sudo ufw allow from <your_ip> to any port 80; sudo ufw deny 80; sudo ufw enable"
echo "AWS: Add Security Group rule 'HTTP, TCP, 80, <your_ip>/32'."
echo -e "$(get_language_message "\e[96mInitializing DVWA database...\e[0m" "\e[96mInicializando base de datos DVWA...\e[0m")"
curl -s -o /dev/null "http://localhost/DVWA/setup.php?action=install" || {
    echo -e "$(get_language_message "\e[91mAutomatic database init failed. Visit http://$INPUT_URL/DVWA/setup.php and click 'Create / Reset Database'.\e[0m" "\e[91mFallo en la inicialización automática. Visite http://$INPUT_URL/DVWA/setup.php y haga clic en 'Create / Reset Database'.\e[0m")"
}

# Test setup
echo -e "$(get_language_message "\e[96mTesting DVWA...\e[0m" "\e[96mProbando DVWA...\e[0m")"
curl -s -o /dev/null -w "%{http_code}" http://localhost/DVWA/login.php | grep -q 200 || {
    echo -e "$(get_language_message "\e[91mDVWA test failed. Check /var/log/apache2/error.log.\e[0m" "\e[91mPrueba de DVWA fallida. Revise /var/log/apache2/error.log.\e[0m")"
    exit 1
}
curl -s -o /dev/null -w "%{http_code}" http://localhost/ | grep -q 302 || {
    echo -e "$(get_language_message "\e[91mRedirect test failed. Check Apache config.\e[0m" "\e[91mPrueba de redirección fallida. Revise la configuración de Apache.\e[0m")"
    exit 1
}

# Final message
echo -e "$(get_language_message "\e[92mDVWA installed successfully!\e[0m" "\e[92m¡DVWA instalado con éxito!\e[0m")"
echo -e "$(get_language_message "\e[96mAccess: http://$INPUT_URL/ (redirects to DVWA)\e[0m" "\e[96mAcceso: http://$INPUT_URL/ (redirecciona a DVWA)\e[0m")"
echo -e "$(get_language_message "\e[92mCredentials:\e[0m" "\e[92mCredenciales:\e[0m")"
echo -e "Username: \033[93madmin\033[0m"
echo -e "Password: \033[93mpassword\033[0m"
echo -e "$(get_language_message "\e[93mRestrict port 80: sudo ufw allow from <your_ip> to any port 80; sudo ufw deny 80; sudo ufw enable\e[0m" "\e[93mRestrinja el puerto 80: sudo ufw allow from <su_ip> to any port 80; sudo ufw deny 80; sudo ufw enable\e[0m")"
echo -e "$(get_language_message "\e[93mAWS: Add Security Group rule 'HTTP, TCP, 80, <your_ip>/32'.\e[0m" "\e[93mAWS: Agregue regla de grupo de seguridad 'HTTP, TCP, 80, <su_ip>/32'.\e[0m")"
