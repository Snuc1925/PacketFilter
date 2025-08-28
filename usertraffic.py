import asyncio
import time
from collections import deque
import statistics

TARGET_HOST = "192.168.100.1"
TARGET_PORT = 80
CONNECTIONS = 50
DURATION_SECONDS = 30
STATS_INTERVAL_SECONDS = 5

http_request = (
    "GET / HTTP/1.1\r\n"
    f"Host: {TARGET_HOST}\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
).encode()

# Shared statistics counters
total_bytes_sent = 0
total_bytes_received = 0
total_requests = 0
total_responses = 0
stats_lock = asyncio.Lock()

# For calculating rates
bytes_history = deque()
requests_history = deque()
last_stats_time = 0

async def connection_worker(i):
    global total_bytes_sent, total_bytes_received, total_requests, total_responses
    
    start_time = time.time()
    connection_bytes_sent = 0
    connection_bytes_received = 0
    connection_requests = 0
    connection_responses = 0
    
    try:
        reader, writer = await asyncio.open_connection(TARGET_HOST, TARGET_PORT)
        
        # Keep sending requests until the connection lifetime is reached
        while time.time() - start_time < DURATION_SECONDS:
            # Send request
            writer.write(http_request)
            await writer.drain()
            connection_bytes_sent += len(http_request)
            connection_requests += 1
            
            # Read response without waiting for full response
            try:
                response = await asyncio.wait_for(reader.read(4096), timeout=1.0)
                connection_bytes_received += len(response)
                connection_responses += 1
            except asyncio.TimeoutError:
                # Continue even if we don't get a full response
                pass
                
            # Small delay to prevent overwhelming the server
            await asyncio.sleep(0.01)
            
        # Close the connection properly
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except asyncio.TimeoutError:
            pass
            
    except Exception as e:
        pass
    finally:
        # Update global counters
        async with stats_lock:
            total_bytes_sent += connection_bytes_sent
            total_bytes_received += connection_bytes_received
            total_requests += connection_requests
            total_responses += connection_responses

async def stats_reporter():
    global last_stats_time, total_bytes_sent, total_bytes_received, total_requests, total_responses
    
    last_stats_time = time.time()
    last_bytes = 0
    last_requests = 0
    
    while True:
        await asyncio.sleep(STATS_INTERVAL_SECONDS)
        
        current_time = time.time()
        elapsed = current_time - last_stats_time
        
        async with stats_lock:
            bytes_delta = total_bytes_sent + total_bytes_received - last_bytes
            requests_delta = total_requests - last_requests
            
            bytes_per_second = bytes_delta / elapsed
            requests_per_second = requests_delta / elapsed
            
            print(f"\n=== STATS at {time.strftime('%Y-%m-%d %H:%M:%S')} ===")
            print(f"Connections: {CONNECTIONS}")
            print(f"Bytes per second: {bytes_per_second:.2f} bytes/s")
            print(f"Requests per second: {requests_per_second:.2f} req/s")
            print(f"Total bytes sent: {total_bytes_sent} bytes")
            print(f"Total bytes received: {total_bytes_received} bytes")
            print(f"Total requests: {total_requests}")
            print(f"Total responses: {total_responses}")
            
            # Store for next calculation
            last_bytes = total_bytes_sent + total_bytes_received
            last_requests = total_requests
            
        last_stats_time = current_time

async def connection_manager():
    global total_bytes_sent, total_bytes_received, total_requests, total_responses
    
    print(f"Starting load test with {CONNECTIONS} connections to {TARGET_HOST}:{TARGET_PORT}")
    print(f"Duration: {DURATION_SECONDS}s, Connection lifetime: {DURATION_SECONDS}s")
    print(f"Statistics will be printed every {STATS_INTERVAL_SECONDS} seconds")
    
    start_time = time.time()
    end_time = start_time + DURATION_SECONDS
    
    # Start the stats reporter
    stats_task = asyncio.create_task(stats_reporter())
    
    while time.time() < end_time:
        # Calculate how many connections to create
        async with stats_lock:
            active_tasks = len([task for task in asyncio.all_tasks() 
                              if task != asyncio.current_task() and task != stats_task])
        
        connections_to_create = max(0, CONNECTIONS - active_tasks + 1)  # +1 to account for this task and stats task
        
        if connections_to_create > 0:
            # Create new connections
            new_tasks = [connection_worker(i) for i in range(connections_to_create)]
            for task in new_tasks:
                asyncio.create_task(task)
        
        # Wait a bit before checking again
        await asyncio.sleep(1)
    
    # Wait for the end of the test
    remaining_time = max(0, end_time - time.time())
    if remaining_time > 0:
        print(f"Waiting for remaining connections to finish... ({remaining_time:.1f}s left)")
        await asyncio.sleep(remaining_time)
    
    # Cancel stats reporter
    stats_task.cancel()
    
    # Print final stats
    print("\n=== FINAL STATS ===")
    print(f"Total bytes sent: {total_bytes_sent} bytes")
    print(f"Total bytes received: {total_bytes_received} bytes")
    print(f"Total requests: {total_requests}")
    print(f"Total responses: {total_responses}")
    print(f"Average bytes/s: {(total_bytes_sent + total_bytes_received) / DURATION_SECONDS:.2f}")
    print(f"Average requests/s: {total_requests / DURATION_SECONDS:.2f}")

if __name__ == "__main__":
    try:
        asyncio.run(connection_manager())
    except KeyboardInterrupt:
        print("Load test interrupted by user")