import asyncio
import aiohttp
import time

# --- Configuration ---
TARGET_URL = 'http://192.168.100.1/'
REQUEST_COUNT = 300
CONCURRENT_REQUESTS = 200 # How many requests to run in parallel at a time

# --- Counters for statistics ---
success_count = 0
failure_count = 0

async def send_request(session, url):
    """Sends a single HTTP GET request and handles the outcome."""
    global success_count, failure_count
    try:
        # We set a short timeout. If the BPF filter drops the packet,
        # this request will fail after the timeout, which is the expected behavior.
        # The key is that asyncio won't block other requests during this wait.
        async with session.get(url, timeout=5) as response:
            # You can optionally check the status if a response is received
            if response.status == 200:
                success_count += 1
                # print(f"Success: {response.status}") # Uncomment for verbose success
            else:
                failure_count += 1
                # print(f"Failure: {response.status}") # Uncomment for verbose failure
            # We don't need the body, so we can immediately release the connection
            await response.release()

    except asyncio.TimeoutError:
        # This is the expected outcome if the BPF filter works and drops the packet
        failure_count += 1
        # print("Request timed out (likely dropped by BPF).")
    except aiohttp.ClientError as e:
        # Catches other connection errors (e.g., connection refused)
        failure_count += 1
        # print(f"A client error occurred: {e}")

async def main():
    """Main function to coordinate the flood attack simulation."""
    print(f"Starting HTTP flood simulation with {REQUEST_COUNT} requests to {TARGET_URL}")
    start_time = time.time()

    # aiohttp.ClientSession is used to manage a pool of connections
    async with aiohttp.ClientSession() as session:
        tasks = []
        for i in range(REQUEST_COUNT):
            # Create a task for each request
            task = asyncio.create_task(send_request(session, TARGET_URL))
            tasks.append(task)
        
        # Run all tasks concurrently
        await asyncio.gather(*tasks)

    end_time = time.time()
    duration = end_time - start_time

    print("\n--- Simulation Finished ---")
    print(f"Total requests sent: {REQUEST_COUNT}")
    print(f"Successful responses (200 OK): {success_count}")
    print(f"Failed/Dropped requests: {failure_count}")
    print(f"Total duration: {duration:.2f} seconds")
    if duration > 0:
        print(f"Requests per second (RPS): {REQUEST_COUNT / duration:.2f}")

if __name__ == '__main__':
    # On Windows, you might need this policy if you see errors with many concurrent tasks
    # asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
