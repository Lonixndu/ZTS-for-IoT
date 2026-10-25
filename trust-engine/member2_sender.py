"""Example Member 2 sender. Reuse the exact event, UUID and timestamp on retries."""
from copy import deepcopy
import time
import httpx


def send_event(client, event, token, *, max_attempts=3, sleep=time.sleep):
    if type(max_attempts) is not int or max_attempts < 1:
        raise ValueError('max_attempts must be a positive integer')
    fixed_event = deepcopy(event)
    for attempt in range(max_attempts):
        try:
            response = client.post('/v1/behavior-events', json=fixed_event,
                                   headers={'Authorization': f'Bearer {token}'})
        except httpx.TransportError:
            if attempt == max_attempts - 1:
                raise
        else:
            if response.status_code == 202:
                return response.json()
            if response.status_code != 429 and response.status_code < 500:
                response.raise_for_status()
            if attempt == max_attempts - 1:
                response.raise_for_status()
        sleep(min(0.5 * 2**attempt, 2))
    raise RuntimeError('unexpected retry state')
