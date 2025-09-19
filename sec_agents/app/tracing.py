import logging
import time
import uuid
from functools import wraps
from typing import Any, Callable
from contextlib import contextmanager
import json

logger = logging.getLogger(__name__)


class RequestTracer:
    def __init__(self):
        self.traces = {}

    def start_trace(self, trace_id: str, operation: str, metadata: dict = None):
        self.traces[trace_id] = {
            "trace_id": trace_id,
            "operation": operation,
            "start_time": time.time(),
            "metadata": metadata or {},
            "spans": [],
        }
        logger.info(f"Started trace {trace_id} for operation {operation}")

    def add_span(self, trace_id: str, span_name: str, data: dict = None):
        if trace_id in self.traces:
            span = {
                "span_name": span_name,
                "timestamp": time.time(),
                "data": data or {},
            }
            self.traces[trace_id]["spans"].append(span)
            logger.debug(f"Added span {span_name} to trace {trace_id}")

    def end_trace(self, trace_id: str, result: dict = None, error: str = None):
        if trace_id in self.traces:
            trace = self.traces[trace_id]
            trace["end_time"] = time.time()
            trace["duration"] = trace["end_time"] - trace["start_time"]
            trace["result"] = result
            trace["error"] = error
            trace["status"] = "error" if error else "success"

            logger.info(
                f"Completed trace {trace_id}: {trace['operation']} "
                f"({trace['duration']:.3f}s) - {trace['status']}"
            )

            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"Trace details: {json.dumps(trace, indent=2)}")

    def get_trace(self, trace_id: str) -> dict:
        return self.traces.get(trace_id)


tracer = RequestTracer()


def setup_tracing():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )
    logger.info("Tracing system initialized")


def trace_request(func: Callable) -> Callable:
    @wraps(func)
    async def wrapper(*args, **kwargs):
        trace_id = str(uuid.uuid4())
        operation = f"{func.__module__}.{func.__name__}"

        tracer.start_trace(
            trace_id,
            operation,
            metadata={"args_count": len(args), "kwargs_keys": list(kwargs.keys())},
        )

        try:
            tracer.add_span(trace_id, "execution_start")
            result = await func(*args, **kwargs)
            tracer.add_span(trace_id, "execution_complete", {"result_type": type(result).__name__})
            tracer.end_trace(trace_id, {"success": True})
            return result
        except Exception as e:
            tracer.add_span(trace_id, "error_occurred", {"error": str(e)})
            tracer.end_trace(trace_id, error=str(e))
            raise

    return wrapper


@contextmanager
def trace_operation(operation_name: str, metadata: dict = None):
    trace_id = str(uuid.uuid4())
    tracer.start_trace(trace_id, operation_name, metadata)
    try:
        yield trace_id
        tracer.end_trace(trace_id, {"success": True})
    except Exception as e:
        tracer.end_trace(trace_id, error=str(e))
        raise