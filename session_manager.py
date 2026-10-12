import json
import time
import uuid
import logging
from typing import Optional, Dict
from dataclasses import dataclass, asdict

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class SessionContext:
    session_id: str
    cookies: Dict[str, str]
    headers: Dict[str, str]
    username: str
    expires_at: float
    is_valid: bool = True
    login_url: str = ""
    csrf_token: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, data: str):
        try:
            dict_data = json.loads(data)
            return cls(**dict_data)
        except Exception as e:
            logger.error(f"Failed to deserialize session: {e}")
            return None


class SessionManager:
    def __init__(self, redis_host: str = 'localhost', 
                 redis_port: int = 6379, 
                 redis_db: int = 0,
                 ttl_seconds: int = 3600,
                 refresh_threshold: int = 300,
                 enabled: bool = True):          # 👈 ADD THIS PARAMETER
        """
        Initialize session manager
        
        Args:
            redis_host: Redis host
            redis_port: Redis port
            redis_db: Redis database number
            ttl_seconds: Session TTL in seconds
            refresh_threshold: Refresh threshold in seconds
            enabled: If False, skip Redis and use in-memory storage only
        """
        self.ttl_seconds = ttl_seconds
        self.refresh_threshold = refresh_threshold
        self.redis_client = None
        self.use_redis = False
        self.memory_sessions = {}
        
        # Skip Redis if disabled
        if not enabled:
            logger.debug("Redis disabled via config, using in-memory sessions only")
            return
        
        # Try to connect to Redis
        if REDIS_AVAILABLE:
            try:
                self.redis_client = redis.Redis(
                    host=redis_host, 
                    port=redis_port, 
                    db=redis_db,
                    decode_responses=True,
                    socket_connect_timeout=2,
                    socket_timeout=2
                )
                self.redis_client.ping()
                self.use_redis = True
                logger.debug("✅ Connected to Redis successfully")
            except Exception as e:
                logger.debug(f"Redis unavailable, using in-memory storage: {e}")
                self.redis_client = None
                self.use_redis = False
        else:
            logger.debug("Redis not installed, using in-memory storage")

    # ... (rest of the methods remain exactly the same)
    
    def get_session(self, username: str, role: str = 'default') -> Optional[SessionContext]:
        """Get session from Redis or memory"""
        if self.use_redis and self.redis_client:
            redis_key = f"vapt:session:{role}:{username}"
            session_json = self.redis_client.get(redis_key)
            if session_json:
                try:
                    session = SessionContext.from_json(session_json)
                    if session and self._validate_session(session):
                        return session
                except Exception as e:
                    logger.error(f"Error retrieving session from Redis: {e}")
        
        mem_key = f"{role}:{username}"
        session = self.memory_sessions.get(mem_key)
        if session and self._validate_session(session):
            return session
        
        return None

    def store_session(self, session: SessionContext, role: str = 'default') -> bool:
        """Store session in Redis or memory"""
        try:
            if self.use_redis and self.redis_client:
                redis_key = f"vapt:session:{role}:{session.username}"
                self.redis_client.setex(
                    name=redis_key,
                    time=self.ttl_seconds,
                    value=session.to_json()
                )
            else:
                mem_key = f"{role}:{session.username}"
                self.memory_sessions[mem_key] = session
            return True
        except Exception as e:
            logger.error(f"Error storing session: {e}")
            return False

    def refresh_session(self, username: str, role: str = 'default') -> Optional[SessionContext]:
        """Refresh an existing session"""
        session = self.get_session(username, role)
        if session:
            session.expires_at = time.time() + self.ttl_seconds
            self.store_session(session, role)
            return session
        return None

    def invalidate_session(self, username: str, role: str = 'default') -> bool:
        """Invalidate/delete a session"""
        try:
            if self.use_redis and self.redis_client:
                redis_key = f"vapt:session:{role}:{username}"
                self.redis_client.delete(redis_key)
            else:
                mem_key = f"{role}:{username}"
                if mem_key in self.memory_sessions:
                    del self.memory_sessions[mem_key]
            return True
        except Exception as e:
            logger.error(f"Error invalidating session: {e}")
            return False

    def acquire_lock(self, username: str, role: str = 'default', timeout: int = 10) -> Optional[str]:
        """Acquire a distributed lock"""
        if self.use_redis and self.redis_client:
            lock_key = f"vapt:lock:{role}:{username}"
            lock_value = str(uuid.uuid4())
            acquired = self.redis_client.set(lock_key, lock_value, nx=True, ex=timeout)
            if acquired:
                return lock_value
            return None
        
        lock_key = f"{role}:{username}"
        if lock_key in self.memory_sessions:
            return None
        lock_value = str(uuid.uuid4())
        self.memory_sessions[f"_lock_{lock_key}"] = lock_value
        return lock_value

    def release_lock(self, username: str, role: str = 'default', lock_value: str = None) -> bool:
        """Release a lock"""
        try:
            if self.use_redis and self.redis_client:
                lock_key = f"vapt:lock:{role}:{username}"
                if lock_value:
                    current_value = self.redis_client.get(lock_key)
                    if current_value == lock_value:
                        self.redis_client.delete(lock_key)
                        return True
                else:
                    self.redis_client.delete(lock_key)
                    return True
            else:
                lock_key = f"_lock_{role}:{username}"
                if lock_key in self.memory_sessions:
                    del self.memory_sessions[lock_key]
                    return True
            return False
        except Exception as e:
            logger.error(f"Error releasing lock: {e}")
            return False

    def _validate_session(self, session: SessionContext) -> bool:
        """Check if a session is still valid"""
        if not session or not session.is_valid:
            return False
        if session.expires_at <= time.time():
            return False
        return True

    def wait_for_session(self, username: str, role: str = 'default', timeout: int = 30) -> Optional[SessionContext]:
        """Wait for another process to complete login"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            session = self.get_session(username, role)
            if session:
                return session
            time.sleep(1)
        return None