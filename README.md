* RAWSNAT/RAWDNAT code is removed from xtables-addons as unmaintained code in version 2.4 https://github.com/nawawi/xtables-addons/commit/9414a5df343bf30ba13e76dbd7181c55683b11cb
* Based on https://github.com/VittGam/xtables-addons-rawnat

## Install (DKMS)

```bash
apt install dkms
apt install linux-headers-$(uname -r)

git clone https://github.com/imena/xtables-addons-rawnat /usr/src/xtables-addon-rawnat-20190902

dkms add -m xtables-addon-rawnat -v 20190902
dkms build -m xtables-addon-rawnat -v 20190902
dkms install -m xtables-addon-rawnat -v 20190902

echo "xt_RAWNAT" > /etc/modules-load.d/rawnat.conf
```