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


wget https://repo.fastpanel.direct/install_fastpanel.sh -O - | bash -




.


