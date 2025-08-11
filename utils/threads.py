import threading
import queue
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Any, Dict, Optional
import logging
from functools import wraps
import os

logger = logging.getLogger(__name__)

class ThreadSafeCounter:
    """Thread-safe counter for tracking progress"""
    
    def __init__(self, initial_value: int = 0):
        self._value = initial_value
        self._lock = threading.Lock()
    
    def increment(self, amount: int = 1) -> int:
        """Increment counter by amount and return new value"""
        with self._lock:
            self._value += amount
            return self._value
    
    def decrement(self, amount: int = 1) -> int:
        """Decrement counter by amount and return new value"""
        with self._lock:
            self._value -= amount
            return self._value
    
    @property
    def value(self) -> int:
        """Get current counter value"""
        with self._lock:
            return self._value
    
    def set(self, value: int) -> None:
        """Set counter to specific value"""
        with self._lock:
            self._value = value

class ProgressTracker:
    """Track progress across multiple threads"""
    
    def __init__(self, total_items: int, description: str = "Processing"):
        self.total = total_items
        self.description = description
        self.counter = ThreadSafeCounter(0)
        self.start_time = time.time()
        self.lock = threading.Lock()
    
    def update(self, amount: int = 1) -> None:
        """Update progress"""
        current = self.counter.increment(amount)
        if current % 100 == 0 or current == self.total:  # Log every 100 items or when complete
            self._log_progress(current)
    
    def _log_progress(self, current: int) -> None:
        """Log progress with percentage and ETA"""
        elapsed = time.time() - self.start_time
        if current > 0:
            percentage = (current / self.total) * 100
            if elapsed > 0:
                rate = current / elapsed
                eta = (self.total - current) / rate if rate > 0 else 0
                eta_str = f"ETA: {eta:.1f}s"
            else:
                eta_str = "ETA: calculating..."
            
            logger.info(f"{self.description}: {current}/{self.total} ({percentage:.1f}%) - {eta_str}")

class ThreadPoolManager:
    """Manage thread pool for parallel processing"""
    
    def __init__(self, max_workers: int = None, thread_name_prefix: str = "PCAPWorker"):
        self.max_workers = max_workers or min(32, (os.cpu_count() or 1) + 4)
        self.thread_name_prefix = thread_name_prefix
        self.executor = None
        self.active_tasks = []
    
    def __enter__(self):
        """Context manager entry"""
        self.executor = ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix=self.thread_name_prefix
        )
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        if self.executor:
            self.executor.shutdown(wait=True)
    
    def submit(self, func: Callable, *args, **kwargs):
        """Submit a task to the thread pool"""
        if not self.executor:
            raise RuntimeError("ThreadPoolManager not initialized. Use as context manager.")
        
        future = self.executor.submit(func, *args, **kwargs)
        self.active_tasks.append(future)
        return future
    
    def map(self, func: Callable, iterable, chunksize: int = 1):
        """Map function over iterable using thread pool"""
        if not self.executor:
            raise RuntimeError("ThreadPoolManager not initialized. Use as context manager.")
        
        return self.executor.map(func, iterable, chunksize=chunksize)
    
    def wait_for_completion(self, timeout: Optional[float] = None):
        """Wait for all submitted tasks to complete"""
        if not self.active_tasks:
            return
        
        done, not_done = as_completed(self.active_tasks, timeout=timeout)
        
        # Handle completed tasks
        for future in done:
            try:
                result = future.result()
                # Log successful completion
                logger.debug(f"Task completed successfully: {future}")
            except Exception as e:
                logger.error(f"Task failed with error: {e}")
        
        # Cancel any remaining tasks if timeout occurred
        if not_done:
            for future in not_done:
                future.cancel()
            logger.warning(f"Cancelled {len(not_done)} tasks due to timeout")

def parallel_process(items: List[Any], 
                    process_func: Callable, 
                    max_workers: int = None,
                    chunk_size: int = 1,
                    progress_callback: Optional[Callable] = None) -> List[Any]:
    """Process items in parallel using thread pool"""
    
    results = []
    max_workers = max_workers or min(32, (os.cpu_count() or 1) + 4)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        futures = [executor.submit(process_func, item) for item in items]
        
        # Collect results as they complete
        for i, future in enumerate(as_completed(futures)):
            try:
                result = future.result()
                results.append(result)
                
                if progress_callback:
                    progress_callback(i + 1, len(items))
                    
            except Exception as e:
                logger.error(f"Error processing item {i}: {e}")
                results.append(None)
    
    return results

def batch_process(items: List[Any], 
                  process_func: Callable, 
                  batch_size: int = 100,
                  max_workers: int = None) -> List[Any]:
    """Process items in batches to control memory usage"""
    
    results = []
    total_batches = (len(items) + batch_size - 1) // batch_size
    
    for batch_num in range(total_batches):
        start_idx = batch_num * batch_size
        end_idx = min(start_idx + batch_size, len(items))
        batch_items = items[start_idx:end_idx]
        
        logger.info(f"Processing batch {batch_num + 1}/{total_batches} ({len(batch_items)} items)")
        
        batch_results = parallel_process(
            batch_items, 
            process_func, 
            max_workers=max_workers
        )
        results.extend(batch_results)
    
    return results

def retry_on_failure(max_retries: int = 3, delay: float = 1.0):
    """Decorator to retry function on failure"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {delay}s...")
                        time.sleep(delay)
                        delay *= 2  # Exponential backoff
            
            logger.error(f"All {max_retries} attempts failed. Last error: {last_exception}")
            raise last_exception
        
        return wrapper
    return decorator

def timeout_handler(timeout_seconds: float):
    """Decorator to add timeout to function execution"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            import signal
            
            def timeout_signal_handler(signum, frame):
                raise TimeoutError(f"Function {func.__name__} timed out after {timeout_seconds} seconds")
            
            # Set up signal handler for timeout
            old_handler = signal.signal(signal.SIGALRM, timeout_signal_handler)
            signal.alarm(int(timeout_seconds))
            
            try:
                result = func(*args, **kwargs)
                signal.alarm(0)  # Cancel alarm
                return result
            finally:
                signal.signal(signal.SIGALRM, old_handler)
        
        return wrapper
    return decorator

class WorkerThread(threading.Thread):
    """Custom worker thread with result collection"""
    
    def __init__(self, target: Callable, args: tuple = (), kwargs: dict = None, 
                 result_queue: queue.Queue = None, name: str = None):
        super().__init__(target=target, args=args, kwargs=kwargs or {}, name=name)
        self.result_queue = result_queue or queue.Queue()
        self.exception = None
        self.result = None
    
    def run(self):
        """Override run method to capture exceptions and results"""
        try:
            self.result = self._target(*self._args, **self._kwargs)
            if self.result_queue:
                self.result_queue.put(("success", self.result))
        except Exception as e:
            self.exception = e
            if self.result_queue:
                self.result_queue.put(("error", str(e)))
            logger.error(f"Worker thread {self.name} failed: {e}")
    
    def get_result(self, timeout: Optional[float] = None):
        """Get result from result queue"""
        try:
            status, result = self.result_queue.get(timeout=timeout)
            if status == "error":
                raise RuntimeError(f"Worker thread failed: {result}")
            return result
        except queue.Empty:
            raise TimeoutError(f"Worker thread {self.name} timed out")

def create_worker_pool(num_workers: int, 
                       target_func: Callable, 
                       args_list: List[tuple],
                       kwargs_list: List[dict] = None) -> List[WorkerThread]:
    """Create a pool of worker threads"""
    
    if kwargs_list is None:
        kwargs_list = [{}] * len(args_list)
    
    if len(args_list) != len(kwargs_list):
        raise ValueError("args_list and kwargs_list must have the same length")
    
    workers = []
    for i in range(min(num_workers, len(args_list))):
        worker = WorkerThread(
            target=target_func,
            args=args_list[i],
            kwargs=kwargs_list[i],
            name=f"Worker-{i}"
        )
        workers.append(worker)
    
    return workers

def run_worker_pool(workers: List[WorkerThread], 
                    start_delay: float = 0.1) -> List[Any]:
    """Run a pool of worker threads and collect results"""
    
    # Start all workers
    for worker in workers:
        worker.start()
        time.sleep(start_delay)  # Stagger start times
    
    # Wait for all workers to complete
    for worker in workers:
        worker.join()
    
    # Collect results
    results = []
    for worker in workers:
        try:
            result = worker.get_result(timeout=1.0)
            results.append(result)
        except Exception as e:
            logger.error(f"Failed to get result from {worker.name}: {e}")
            results.append(None)
    
    return results
