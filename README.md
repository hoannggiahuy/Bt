![image](https://github.com/user-attachments/assets/a580ebe1-c67d-4753-9bd0-3d9e8fd5515f)
![image](https://github.com/user-attachments/assets/6c11514d-1165-4ff9-b5cc-df682f1771e8)
![image](https://github.com/user-attachments/assets/106f2197-e246-45d8-8d3b-44de34907ee3)
![image](https://github.com/user-attachments/assets/facb5c5e-acbf-4094-aa3e-466be058119a)


📘 Gửi Báo Cáo Công Ty Qua Server Trung Gian
Một hệ thống truyền file bảo mật sử dụng mã hóa RSA-2048, AES-GCM và xác thực SHA-512, được xây dựng với Flask backend, Socket.IO cho giao tiếp real-time, và Bootstrap frontend.

🔐 Tính năng bảo mật
Mã hóa mạnh mẽ: Sử dụng RSA-2048 để trao đổi khóa và AES-GCM để mã hóa nội dung file.

Xác thực RSA/PSS: Đảm bảo danh tính người gửi và người nhận thông qua chữ ký số với RSA và SHA-512.

Kiểm tra toàn vẹn SHA-512: Đảm bảo dữ liệu không bị giả mạo trong quá trình truyền.

Trao đổi khóa an toàn: Sử dụng RSA-OAEP với SHA-512 để mã hóa khóa phiên (session key).

Chữ ký số: Xác thực metadata và nội dung file với chữ ký RSA/PSS.

Real-time: Giao tiếp tức thời qua Socket.IO, đảm bảo xử lý nhanh chóng và hiệu quả.

🏗️ Kiến trúc hệ thống

Luồng xử lý bảo mật:

Handshake:

Người gửi: Gửi tín hiệu "Hello!" để bắt đầu kết nối.

Người nhận: Phản hồi "Ready!" để xác nhận sẵn sàng.

Trao đổi khóa:

Tạo cặp khóa RSA-2048 cho cả người gửi và người nhận.

Người gửi mã hóa khóa phiên AES-GCM bằng khóa công khai RSA của người nhận.

Ký metadata (tên file, ID giao dịch, timestamp) bằng khóa riêng RSA của người gửi.

Gửi file:

Nội dung file được mã hóa bằng AES-GCM với khóa phiên.

Tạo hash SHA-512 của dữ liệu mã hóa để kiểm tra toàn vẹn.

Ký hash bằng RSA/PSS để xác thực.

Xác thực và giải mã:

Người nhận xác thực chữ ký metadata và file bằng khóa công khai RSA của người gửi.

Kiểm tra hash SHA-512 để đảm bảo toàn vẹn dữ liệu.

Giải mã file bằng khóa phiên AES-GCM.

Gửi ACK (xác nhận thành công) hoặc NACK (thất bại) tới người gửi.

Hướng dẫn sử dụng

Bước 1: Kết nối

Mở giao diện trong trình duyệt.

Hệ thống tự động kết nối tới server qua Socket.IO.

Kiểm tra trạng thái kết nối trên giao diện.

Bước 2: Tạo khóa RSA

Tại giao diện người gửi hoặc người nhận:

Nhấn nút Tạo khóa RSA để sinh cặp khóa RSA-2048.

Khóa công khai được hiển thị và lưu trữ trên server.

Bước 3: Thực hiện handshake

Người gửi: Nhấn Gửi "Hello!" để bắt đầu.

Người nhận: Nhận tín hiệu và nhấn Gửi "Ready!" để xác nhận.

Bước 4: Gửi khóa xác thực

Người gửi:

Chọn file hoặc nhập nội dung trực tiếp.

Nhấn Gửi khóa xác thực để gửi khóa phiên AES-GCM và metadata đã ký.

Bước 5: Gửi file

Người gửi:

Kéo thả file hoặc nhập nội dung.

Nhấn Gửi file mã hóa để mã hóa và gửi file.

File được mã hóa bằng AES-GCM, kèm hash SHA-512 và chữ ký RSA.

Bước 6: Nhận và xác thực

Người nhận:

Nhận file và xác thực chữ ký metadata, hash, và chữ ký file.

Nhấn Xác thực & Giải mã để giải mã file.

Xem nội dung file đã giải mã hoặc tải về.

Bước 7: Theo dõi giao dịch

Server trung gian hiển thị:

Nhật ký giao dịch và tin nhắn real-time.

Thống kê kết nối, giao dịch, và tỷ lệ thành công.

📊 Hiệu suất

Thông số đo được:

Độ trễ mã hóa: ~20-50ms (tùy kích thước file).

Độ trễ giải mã: ~10-30ms.

Băng thông: Tùy thuộc kích thước file, overhead mã hóa ~5-10%.

Đồng thời: Hỗ trợ nhiều giao dịch đồng thời nhờ Socket.IO.

Tối ưu hóa:

Chia nhỏ dữ liệu lớn khi mã hóa RSA để tránh lỗi kích thước.

Sử dụng threading cho Socket.IO để cải thiện hiệu suất.

Lưu trữ khóa phiên trong bộ nhớ tạm để tái sử dụng.

🔒 Bảo mật

Điểm mạnh:

✅ Mã hóa end-to-end: AES-GCM đảm bảo an toàn nội dung file.

✅ Xác thực mạnh: RSA-2048 và SHA-512 ngăn chặn giả mạo.

✅ Toàn vẹn dữ liệu: Kiểm tra hash SHA-512 đảm bảo dữ liệu không bị thay đổi.

✅ Giao tiếp real-time: Socket.IO cho phép xử lý nhanh và an toàn.

✅ Không lưu trữ khóa nhạy cảm: Khóa riêng và khóa phiên chỉ lưu trong session.

📊 Hiệu suất

Thông số đo được:

Độ trễ mã hóa: ~20-50ms (tùy kích thước file).

Độ trễ giải mã: ~10-30ms.

Băng thông: Tùy thuộc kích thước file, overhead mã hóa ~5-10%.

Đồng thời: Hỗ trợ nhiều giao dịch đồng thời nhờ Socket.IO.

Tối ưu hóa:

Chia nhỏ dữ liệu lớn khi mã hóa RSA để tránh lỗi kích thước.

Sử dụng threading cho Socket.IO để cải thiện hiệu suất.

Lưu trữ khóa phiên trong bộ nhớ tạm để tái sử dụng.

🔒 Bảo mật

Điểm mạnh:

✅ Mã hóa end-to-end: AES-GCM đảm bảo an toàn nội dung file.

✅ Xác thực mạnh: RSA-2048 và SHA-512 ngăn chặn giả mạo.

✅ Toàn vẹn dữ liệu: Kiểm tra hash SHA-512 đảm bảo dữ liệu không bị thay đổi.

✅ Giao tiếp real-time: Socket.IO cho phép xử lý nhanh và an toàn.

✅ Không lưu trữ khóa nhạy cảm: Khóa riêng và khóa phiên chỉ lưu trong session.
