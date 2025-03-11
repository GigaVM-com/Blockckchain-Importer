# Blockckchain-Importer

A modern web-based interface for importing and monitoring Bitcoin blockchain data. Built with PHP 7.4+ and designed for optimal performance with aaPanel's LAMP stack.

Currently can sync Blocks, tx_inputs, tx_outputs, transactions, and address_balances (Depending on Coins Available support)
Tested to Sync blocks, transactions for hthcoin (Dash like)
Tested to sync blocks, address_balances, transactions, tx_inputs, tx_outputs for titcoin (Older fork off of Bitcoin core / Original chain not tittycoin chain)

There is a CLI file import_blockchain.php that can be ran from terminal using php or using cron but has not been thouroughly tested.

## Features

- 🔄 Real-time blockchain import monitoring
- 📊 Live progress tracking and ETA calculations
- 🔐 Secure authentication system
- ⚡ Performance optimization controls
- 🎛️ Adjustable import parameters
- 🔔 Sound notifications for important events
- 📝 Detailed logging
- 🔒 Process locking to prevent concurrent imports - Not currently working
- 🔄 Auto-continue functionality for new blocks / Initial Syncing
- 📈 System resource monitoring

## Requirements

### Standard Requirements
- PHP 7.4 or higher
- MySQL/MariaDB
- Bitcoin Core / Dash like wallet (with RPC enabled)
- Apache2 with mod_rewrite
- PHP Extensions:
  - curl
  - json
  - mysqli
  - openssl
  - bcmath

### Optional Requirements
- PHP Extension: sysinfo (for enhanced system monitoring)
- PHP Extension: gmp (for improved mathematical operations)
- Redis (for enhanced caching)
- PHP Functions:
  - shell_exec (for I/O wait monitoring)
- System Tools:
  - sysstat package (for iostat command)

## Tested Environment
- Ubuntu 24.04 2 core 4gb ram 2tb standard hdd
- aaPanel LAMP stack (default configuration)
- PHP 7.4
- Mysql 8+
- Apache 2.4+

- Achieved a max import speed of 35,500 Blocks per Minute.
## Installation

1. Clone the repository:
```bash
git clone https://github.com/GigaVM-com/Blockckchain-Importer.git
```

2. Set directory permissions:
```bash
# Set directory permissions
chmod 755 /path/to/importer

# Create configuration directory/file with web server write permissions
touch /path/to/importer/importer.conf
chown www:www /path/to/importer/importer.conf

3. Configure Wallet:
```conf
# wallet.conf
tx-index=1
datadir=set_if_needed
server=1
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=8332
rpcuser=rpcuser
rpcpassword=rpcpass
maxconnections=1023
```

## Configuration

### Basic Configuration
Has a initial setup when you navigate to import_blockchain_web.php or you can manually add the details into importer.conf details below.
Edit `importer.conf` with your settings:
```ini
; Database Configuration
DB_HOST=localhost
DB_NAME=your_database
DB_USER=your_user
DB_PASS="your_password"

; RPC Configuration
RPC_USER=your_rpc_user
RPC_PASSWORD="your_rpc_password"
RPC_HOST=127.0.0.1
RPC_PORT=8332

; Admin Configuration
ADMIN_PASSWORD="your_secure_password"
```

### Performance Optimization

#### Memory Management
- Adjust `MAX_MEMORY` based on available system resources
- Configure batch sizes for optimal throughput
- Set appropriate cache limits

#### Database Optimization
- Enable InnoDB buffer pool
- Optimize table indexes
- Configure proper transaction isolation levels

#### Network Settings
- Adjust RPC batch sizes
- Configure connection timeouts
- Set appropriate retry parameters

## Usage

1. Access the web interface:
```
http://your-server/path/to/importer/
```

2. Log in using your admin password

3. Configure import settings:
   - Batch size
   - Processing delay
   - Memory buffer
   - Thread allocation

4. Start the import process

## Security Considerations

- Use strong passwords
- Keep configuration files secure
- Regularly update dependencies
- Monitor system logs
- Implement proper firewall rules

## Troubleshooting

### Common Issues
- Memory limits
- Database connection errors
- RPC timeout issues
- Permission problems

### Solutions
- Check error logs
- Verify configuration
- Monitor system resources
- Validate permissions

## Credits

### Libraries and Code Sources
- **EasyBitcoin-PHP**: Original work by Andrew LeCody, which served as inspiration for our modern RPC client
- **Bootstrap**: Frontend framework by Twitter, Inc.
- **jQuery**: JavaScript library by jQuery Foundation
- **Chart.js**: Charting library by Chart.js contributors

### Contributors
- [Your Name/Organization]
- Community contributors

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This software has been tested primarily with aaPanel's default LAMP stack configuration. While it may work with other setups, additional configuration might be required.

## Support

For issues, feature requests, or contributions:
- Open an issue
- Submit a pull request
- Contact the maintainers

---

**Note**: This project is not affiliated with Bitcoin Core, HTH coin, Titcoin or aaPanel.
