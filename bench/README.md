TidesDB always appends to WAL.  This cannot be deactivated.  The WAL is used to recover from crashes and previous state.

Below is an example running the benchmark on a Ubunch machine with an Intel i7-11700K CPU and 48GB of RAM non SSD storage ( WDC WDS500G2B0A-00SM50(HDD) )
```
            .-/+oossssoo+/-.
        `:+ssssssssssssssssss+:`           -------------------------------
      -+ssssssssssssssssssyyssss+-         OS: Ubuntu 23.04 x86_64
    .ossssssssssssssssssdMMMNysssso.       Kernel: 6.2.0-39-generic
   /ssssssssssshdmmNNmmyNMMMMhssssss/      Uptime: 20 days, 5 hours, 6 mins
  +ssssssssshmydMMMMMMMNddddyssssssss+     Packages: 3141 (dpkg), 29 (snap)
 /sssssssshNMMMyhhyyyyhmNMMMNhssssssss/    Shell: bash 5.2.15
.ssssssssdMMMNhsssssssssshNMMMdssssssss.   Resolution: 1080x1920, 1920x1080
+sssshhhyNMMNyssssssssssssyNMMMysssssss+   DE: GNOME 44.3
ossyNMMMNyMMhsssssssssssssshmmmhssssssso   WM: Mutter
ossyNMMMNyMMhsssssssssssssshmmmhssssssso   WM Theme: Adwaita
+sssshhhyNMMNyssssssssssssyNMMMysssssss+   Theme: Yaru [GTK2/3]
.ssssssssdMMMNhsssssssssshNMMMdssssssss.   Icons: Yaru [GTK2/3]
 /sssssssshNMMMyhhyyyyhdNMMMNhssssssss/    Terminal: gnome-terminal
  +sssssssssdmydMMMMMMMMddddyssssssss+     CPU: 11th Gen Intel i7-11700K (16) @ 4.900GH
   /ssssssssssshdmNNNNmyNMMMMhssssss/      GPU: AMD ATI Radeon RX 5500/5500M / Pro 5500
    .ossssssssssssssssssdMMMNysssso.       GPU: Intel RocketLake-S GT1 [UHD Graphics 75
      -+sssssssssssssssssyyyssss+-         GPU: NVIDIA GeForce GT 730
        `:+ssssssssssssssssss+:`           Memory: 20929MiB / 47928MiB
            .-/+oossssoo+/-.


1 MILLION PUT, GET, DELETE OPERATIONS

Running PUT benchmark...
PUT benchmark completed in 3.506972 seconds
Running GET benchmark...
GET benchmark completed in 0.077939 seconds
Running DELETE benchmark...
DELETE benchmark completed in 2.976909 seconds
```

