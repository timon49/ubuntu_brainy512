sudo add-apt-repository ppa:mumble/release

sudo apt-get update

sudo apt list mumble 

apt install mumble-server -y


sudo fallocate -l 1G /swapfile 

ls -lh /swapfile

sudo chmod 600 /swapfile

ls -lh /swapfile

sudo mkswap /swapfile

sudo swapon /swapfile

sudo cp /etc/fstab /etc/fstab.bak

echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

apt install htop



wget https://raw.githubusercontent.com/timon49/ubuntu_brainy512/main/_installUbuntu.sh && bash ./_installUbuntu.sh --package=nginx,php73w,bindserver,ffmpeg,imagemagick,certbot,atop,logrotate,MySql5.7,phpMyAdmin-4.9.4,exim,spamassassin,clamav,proftpd


.


