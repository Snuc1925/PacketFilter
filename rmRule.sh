sudo iptables -F # Xóa tất cả các rule trong bảng filter
sudo iptables -X # Xóa tất cả các chain do người dùng định nghĩa
sudo iptables -t nat -F # Xóa rule trong bảng nat
sudo iptables -t nat -X
sudo iptables -t raw -F # Xóa rule trong bảng raw
sudo iptables -t raw -X
sudo iptables -t mangle -F # Xóa rule trong bảng mangle
sudo iptables -t mangle -X
sudo iptables -P INPUT ACCEPT # Đặt chính sách mặc định là chấp nhận
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT

# Nếu bạn đang dùng nftables:
# sudo nft flush ruleset
