# Compile
```bash
gcc synflood.c -o synflood
```

# Help
```
  ______   ___   _       _____ _     ___   ___  ____  
 / ___\ \ / / \ | |     |  ___| |   / _ \ / _ \|  _ \ 
 \___ \\ V /|  \| |_____| |_  | |  | | | | | | | | | |
  ___) || | | |\  |_____|  _| | |__| |_| | |_| | |_| |
 |____/ |_| |_| \_|     |_|   |_____\___/ \___/|____/ 
                                                      
usage: ./synflood [target] [flags]

arguments program:
  -h, -help             Show this help message.
  -v, -verbose          On send verbose mode.

arguments main:
  -delay <ms>           Set delay before send.
  -count <count>        Set count send packets.
  -size <byte>          Set size send packets.
  -window <size>        Set windows size.
  -ttl <count>          Set TTL on IP header.

arguments tcp flags:
  -custom-flags         Reset all default flags.
  -ssyn <1|0>           Set or unset syn flag.
  -sack <1|0>           Set or unset ack flag.
  -sfin <1|0>           Set or unset fin flag.
  -srst <1|0>           Set or unset rst flag.
  -spsh <1|0>           Set or unset psh flag.
  -surg <1|0>           Set or unset urg flag.

arguments type packets:
  -syn                  Set send syn packets.
  -fin                  Set send fin packets.
  -xmas                 Set send xmas packets.
  -null                 Set send null packets.
  -ack                  Set send ack packets.

arguments other:
  -dest-port <port>     Set custom dest port.
  -source-port <port>   Set custom source port.

Created by lomaster & OldTeam
```

# Errors
```
Target only DNS or IP.
Max size arch linux: 1048.
Only sudo run!
```
