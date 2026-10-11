import re
import time
import json
import base64
import threading
import requests
from typing import Optional, Dict, List, Any, Set
from urllib.parse import quote
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context


class TLSAdapter(HTTPAdapter):
    """PadletのCloudflare / TLSフィンガープリント対策 & 並列コネクションプール拡張アダプタ"""
    def __init__(self, pool_connections: int = 32, pool_maxsize: int = 32, **kwargs):
        super().__init__(pool_connections=pool_connections, pool_maxsize=pool_maxsize, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.load_default_certs()
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)


class PadletClient:
    """Padlet 完全内部API専用クライアント (公式有料APIは完全不使用・完全無料稼働)"""

    def __init__(self, api_key: str = "", session_token: str = "", secondary_session_token: str = ""):
        self._token_lock = threading.Lock()
        self._rate_lock = threading.Lock()
        self._token_index = 0
        self._next_allowed = 0.0
        self._token_cooldowns: Dict[str, float] = {}
        self._sessions: Dict[str, requests.Session] = {}
        self.default_session = self._create_session()

        # Bot自身のユーザーIDセット (自己降格・自己削除の完全防止用)
        self.bot_user_ids: Set[str] = set()
        self._probed_tokens: Set[str] = set()
        # Bot自身が作成した投稿IDセット (誤検知完全防止用)
        self.created_post_ids: Set[str] = set()
        self._created_lock = threading.Lock()

        self.owner_id: Optional[str] = None
        self.last_posts_fetch_ok: bool = True
        self.last_comments_fetch_ok: bool = True
        self.last_sections_fetch_ok: bool = True

        self.session_tokens: List[str] = []
        self.set_credentials(
            api_key=api_key,
            session_token=session_token,
            secondary_session_token=secondary_session_token
        )

    def _create_session(self) -> requests.Session:
        s = requests.Session()
        s.mount('https://', TLSAdapter(pool_connections=32, pool_maxsize=32))
        s.mount('http://', HTTPAdapter(pool_connections=16, pool_maxsize=16))
        return s

    @staticmethod
    def _normalize_token(token: str) -> str:
        if not token:
            return ""
        raw = str(token).strip()
        if raw.lower().startswith("bearer "):
            raw = raw[7:].strip()
        return raw

    @staticmethod
    def _extract_uid_from_jwt(raw_token: str) -> Optional[str]:
        """JWT形式のセッショントークンの場合、ペイロードからユーザーIDを抽出"""
        if not raw_token or raw_token.count(".") != 2:
            return None
        try:
            payload_b64 = raw_token.split(".")[1]
            padding = "=" * (-len(payload_b64) % 4)
            decoded = base64.urlsafe_b64decode(payload_b64 + padding).decode("utf-8", errors="ignore")
            data = json.loads(decoded)
            if isinstance(data, dict):
                for key in ("user_id", "userId", "sub", "id", "uid"):
                    val = data.get(key)
                    if val is not None and str(val).strip():
                        return str(val).strip()
        except Exception:
            pass
        return None

    def set_credentials(self, api_key: str = "", session_token: str = "", secondary_session_token: str = ""):
        raw_list = [
            self._normalize_token(session_token),
            self._normalize_token(secondary_session_token),
            self._normalize_token(api_key)
        ]
        deduped: List[str] = []
        for t in raw_list:
            if t and t not in deduped:
                deduped.append(t)
                jwt_uid = self._extract_uid_from_jwt(t)
                if jwt_uid:
                    self.bot_user_ids.add(jwt_uid)

        with self._token_lock:
            self.session_tokens = deduped
            for t in deduped:
                if t not in self._sessions:
                    self._sessions[t] = self._create_session()

    def _select_token_and_session(self) -> tuple[str, requests.Session]:
        """レート制限クールダウンを考慮して最適なアカウントトークンと専用Sessionを選択"""
        with self._token_lock:
            if not self.session_tokens:
                return "", self.default_session

            now = time.time()
            n = len(self.session_tokens)
            selected_token = ""
            for _ in range(n):
                candidate = self.session_tokens[self._token_index % n]
                self._token_index += 1
                cooldown_until = self._token_cooldowns.get(candidate, 0.0)
                if now >= cooldown_until:
                    selected_token = candidate
                    break

            if not selected_token:
                selected_token = min(self.session_tokens, key=lambda t: self._token_cooldowns.get(t, 0.0))

            sess = self._sessions.get(selected_token)
            if sess is None:
                sess = self._create_session()
                self._sessions[selected_token] = sess
            return selected_token, sess

    def _build_headers(self, raw_token: str) -> Dict[str, str]:
        """内部 API (padlet.com) 用ヘッダー (ブラウザ完全模倣)"""
        headers = {
            'Accept': 'application/json, application/vnd.api+json',
            'Accept-Language': 'ja,en-US;q=0.9,en;q=0.8',
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Origin': 'https://padlet.com',
            'Referer': 'https://padlet.com/',
            'Sec-Ch-Ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin'
        }
        if raw_token:
            headers['Authorization'] = f"Bearer {raw_token}"
        return headers

    def _get_internal_headers(self) -> Dict[str, str]:
        token, _ = self._select_token_and_session()
        return self._build_headers(token)

    @staticmethod
    def _parse_retry_after(val: Optional[str], default: float = 1.5) -> float:
        if not val:
            return default
        try:
            parsed = float(val)
            return max(0.2, min(parsed, 10.0))
        except (ValueError, TypeError):
            return default

    def _handle_rate_limit(self, response: requests.Response, token: str = ""):
        """レート制限ヘッダーに応じてトークン別の待機時刻を安全に設定"""
        now = time.time()
        if response.status_code == 429:
            wait_time = self._parse_retry_after(response.headers.get("Retry-After"), default=1.5)
            with self._rate_lock:
                if token:
                    self._token_cooldowns[token] = now + wait_time
                else:
                    self._next_allowed = now + wait_time
            return

        remaining = response.headers.get("X-RateLimit-Remaining")
        reset_time = response.headers.get("X-RateLimit-Reset")
        if remaining is not None:
            try:
                if int(remaining) <= 2:
                    wait_sec = 0.4
                    if reset_time:
                        try:
                            rt = float(reset_time)
                            if rt > 1_000_000_000:
                                wait_sec = max(0.1, min(rt - now + 0.1, 3.0))
                            else:
                                wait_sec = max(0.1, min(rt, 3.0))
                        except (ValueError, TypeError):
                            wait_sec = 0.4
                    with self._rate_lock:
                        if token:
                            self._token_cooldowns[token] = max(self._token_cooldowns.get(token, 0.0), now + wait_sec)
                        else:
                            self._next_allowed = max(self._next_allowed, now + wait_sec)
            except (ValueError, TypeError):
                pass

    def request(self, method: str, url: str, is_official: bool = False, **kwargs) -> requests.Response:
        """内部APIレートリミットを考慮した安全・高速なHTTPリクエスト実行 (429自動リトライ＆別トークン即時フェイルオーバー)"""
        max_retries = 3
        last_response: Optional[requests.Response] = None

        for attempt in range(max_retries):
            token, sess = self._select_token_and_session()

            with self._rate_lock:
                now = time.time()
                token_wait = self._token_cooldowns.get(token, 0.0) - now if token else 0.0
                global_wait = self._next_allowed - now
                wait = max(token_wait, global_wait)

            if wait > 0:
                time.sleep(min(wait, 2.5))

            headers = self._build_headers(token)
            if 'headers' in kwargs and kwargs['headers']:
                headers.update(kwargs['headers'])

            timeout = kwargs.get('timeout', 10)
            req_kwargs = {k: v for k, v in kwargs.items() if k not in ('headers', 'timeout')}

            try:
                sess.cookies.clear()
                response = sess.request(method, url, headers=headers, timeout=timeout, **req_kwargs)
                last_response = response
                self._handle_rate_limit(response, token=token)

                if response.status_code == 429 and attempt < max_retries - 1:
                    if len(self.session_tokens) > 1 and attempt == 0:
                        time.sleep(0.05)
                    else:
                        backoff = self._parse_retry_after(response.headers.get("Retry-After"), default=0.6 * (attempt + 1))
                        time.sleep(min(backoff, 2.5))
                    continue

                return response
            except requests.RequestException:
                if attempt == max_retries - 1:
                    raise
                time.sleep(0.3 * (attempt + 1))

        return last_response  # type: ignore

    def ensure_bot_user_ids(self) -> Set[str]:
        """設定されている管理トークン自身のユーザーID・usernameを取得・キャッシュ（自己処罰・自己降格防止）"""
        with self._token_lock:
            tokens = list(self.session_tokens)

        for t in tokens:
            if not t or t in self._probed_tokens:
                continue
            self._probed_tokens.add(t)
            for ep in ("https://padlet.com/api/5/me", "https://padlet.com/api/10/me", "https://padlet.com/api/9/me"):
                try:
                    res = self.default_session.get(ep, headers=self._build_headers(t), timeout=5)
                    if res.status_code == 200:
                        rj = res.json()
                        data = rj.get("data", rj) if isinstance(rj, dict) else {}
                        if isinstance(data, dict):
                            attrs = data.get("attributes") if isinstance(data.get("attributes"), dict) else data
                            for id_k in ("id", "user_id", "hashid"):
                                val = data.get(id_k) or attrs.get(id_k)
                                if val is not None and str(val).strip():
                                    self.bot_user_ids.add(str(val).strip())
                            uname = attrs.get("username") or data.get("username")
                            if uname and str(uname).strip():
                                self.bot_user_ids.add(str(uname).strip().lower())
                        break
                except Exception:
                    continue
        return self.bot_user_ids

    # -------------------------------------------------------------
    # ボード URL 自動解決
    # -------------------------------------------------------------
    @staticmethod
    def _extract_wall_fields(rj: Any) -> Dict[str, Any]:
        """/api/5/walls または /api/10/walls の様々なJSON構造から属性を統一抽出"""
        if not isinstance(rj, dict):
            return {}
        data = rj.get("data") if isinstance(rj.get("data"), dict) else rj
        attrs = data.get("attributes") if isinstance(data.get("attributes"), dict) else data
        rels = data.get("relationships") if isinstance(data.get("relationships"), dict) else {}

        wall_id = data.get("id") or attrs.get("id") or rj.get("id")
        wall_hashid = attrs.get("hashid") or data.get("hashid") or rj.get("hashid")
        title = attrs.get("title") or attrs.get("name") or data.get("title") or rj.get("title")
        address = attrs.get("address") or data.get("address") or ""

        bg = attrs.get("background") or data.get("background") or {}
        bg_url = bg.get("url") if isinstance(bg, dict) else (bg if isinstance(bg, str) else None)

        # 部屋主(オーナー)IDの網羅的抽出
        owner_id = None
        for obj_key in ("builder", "owner", "user", "creator", "author"):
            obj = attrs.get(obj_key) or data.get(obj_key)
            if isinstance(obj, dict) and obj.get("id") is not None:
                owner_id = str(obj.get("id")).strip()
                break
        if not owner_id:
            for id_key in ("owner_id", "user_id", "creator_id", "builder_id", "author_id"):
                val = attrs.get(id_key) or data.get(id_key) or rj.get(id_key)
                if val is not None and str(val).strip():
                    owner_id = str(val).strip()
                    break
        if not owner_id and rels:
            for rel_key in ("user", "builder", "owner", "creator", "author"):
                rel_data = rels.get(rel_key, {}).get("data")
                if isinstance(rel_data, dict) and rel_data.get("id") is not None:
                    owner_id = str(rel_data.get("id")).strip()
                    break

        return {
            "wall_id": int(wall_id) if (wall_id is not None and str(wall_id).isdigit()) else wall_id,
            "wall_hashid": str(wall_hashid).strip() if wall_hashid else None,
            "title": str(title).strip() if title else None,
            "background_url": bg_url,
            "address": address,
            "owner_id": owner_id
        }

    def resolve_board(self, input_str: str) -> Optional[Dict[str, Any]]:
        """
        PadletのURL (例: https://padlet.com/username/xxxxxx) または 数値ID または slug から、
        wall_id (数値), wall_hashid (英数字文字列), タイトル, 背景画像, オーナーIDを取得・解決する。
        """
        if not input_str:
            return None
        raw = str(input_str).strip()
        clean_url = raw.split('?')[0].split('#')[0].rstrip('/')

        wall_id = None
        title = None
        wall_hashid = None
        extracted: Dict[str, Any] = {}

        if clean_url.isdigit():
            wall_id = int(clean_url)

        if not wall_id and ("padlet.com" in clean_url or "padlet.org" in clean_url or "/" in clean_url):
            target_url = clean_url if clean_url.startswith("http") else f"https://{clean_url}"
            encoded = quote(target_url, safe="")
            link_api = f"https://padlet.com/api/1/links?url={encoded}"
            try:
                res = self.request('GET', link_api)
                if res.status_code == 200:
                    rj = res.json()
                    ldata = rj.get("data", rj) if isinstance(rj, dict) else {}
                    if isinstance(ldata, dict):
                        lattrs = ldata.get("attributes", {}) if isinstance(ldata.get("attributes"), dict) else ldata
                        lid = str(lattrs.get("wall_id") or ldata.get("id") or "")
                        m = re.search(r'\d+', lid)
                        if m:
                            wall_id = int(m.group(0))
                        if lattrs.get("wall_hashid") or lattrs.get("hashid"):
                            wall_hashid = str(lattrs.get("wall_hashid") or lattrs.get("hashid")).strip()
                        if lattrs.get("title"):
                            title = str(lattrs.get("title")).strip()
            except Exception:
                pass

        if (not wall_id or not wall_hashid) and ("padlet.com" in clean_url or "padlet.org" in clean_url or "/" in clean_url):
            target_url = clean_url if clean_url.startswith("http") else f"https://{clean_url}"
            try:
                res = self.default_session.get(target_url, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
                }, timeout=10)
                if res.status_code == 200:
                    html_text = res.text
                    if not wall_id:
                        for pat in (r'wallId["\'\:\s]+([0-9]+)', r'wall_id["\'\:\s]+([0-9]+)', r'"wall"\s*:\s*\{[^}]*"id"\s*:\s*([0-9]+)'):
                            m = re.search(pat, html_text)
                            if m:
                                wall_id = int(m.group(1))
                                break
                    if not wall_hashid:
                        mh = re.search(r'"hashid"\s*:\s*"([a-zA-Z0-9_-]{6,32})"', html_text)
                        if mh:
                            wall_hashid = mh.group(1)
                    if not title:
                        mt = re.search(r'<title>(.*?)</title>', html_text, re.IGNORECASE | re.DOTALL)
                        if mt:
                            title = mt.group(1).replace(" - Padlet", "").strip()
            except Exception:
                pass

        lookup_targets = []
        if wall_id:
            lookup_targets.append(f"https://padlet.com/api/5/walls/{wall_id}")
            lookup_targets.append(f"https://padlet.com/api/10/walls/{wall_id}")
        if wall_hashid:
            lookup_targets.append(f"https://padlet.com/api/10/walls/{wall_hashid}")
            lookup_targets.append(f"https://padlet.com/api/5/walls/{wall_hashid}")

        for ep in lookup_targets:
            try:
                res = self.request('GET', ep)
                if res.status_code == 200:
                    info = self._extract_wall_fields(res.json())
                    if info.get("wall_id") and not wall_id:
                        wall_id = info["wall_id"]
                    if info.get("wall_hashid") and not wall_hashid:
                        wall_hashid = info["wall_hashid"]
                    if info.get("title") and not title:
                        title = info["title"]
                    for k, v in info.items():
                        if v and not extracted.get(k):
                            extracted[k] = v
                    if wall_id and wall_hashid and extracted.get("owner_id"):
                        break
            except Exception:
                continue

        if wall_id and wall_hashid:
            owner_id = extracted.get("owner_id")
            if owner_id:
                self.owner_id = str(owner_id)
            return {
                "wall_id": int(wall_id) if str(wall_id).isdigit() else wall_id,
                "wall_hashid": str(wall_hashid),
                "title": title or extracted.get("title") or f"Padlet ({wall_id})",
                "background_url": extracted.get("background_url"),
                "address": extracted.get("address", ""),
                "owner_id": str(owner_id) if owner_id else None
            }

        return None

    def get_access_settings(self, wall_hashid: str) -> Dict[str, Any]:
        """部屋全体のアクセス権限 (visitorRole, password, requireLogin 等) を取得"""
        if not wall_hashid:
            return {}
        try:
            res = self.request('GET', f"https://padlet.com/api/10/walls/{wall_hashid}/access-settings")
            if res.status_code == 200:
                rj = res.json()
                if isinstance(rj, dict):
                    data = rj.get("data", rj)
                    if isinstance(data, dict):
                        attrs = data.get("attributes") if isinstance(data.get("attributes"), dict) else data
                        if isinstance(attrs, dict):
                            return attrs
        except Exception:
            pass
        return {}

    def detect_custom_properties(self, wall_hashid: str) -> tuple[Optional[str], Optional[str]]:
        """
        最新の投稿を取得し、既存の投稿に投稿フィールド(custom_properties)がある場合は、
        カスタムキーとカスタム値を自動検出して返す。
        """
        if not wall_hashid:
            return None, None
        try:
            res = self.request('GET', f"https://padlet.com/api/10/wishes?wall_hashid={wall_hashid}&page=1&limit=50")
            if res.status_code == 200:
                wishes = res.json().get("data", [])
                for w in wishes:
                    attrs = w.get("attributes", w) if isinstance(w, dict) else {}
                    cp = attrs.get("custom_properties")
                    if cp and isinstance(cp, dict):
                        for k, v in cp.items():
                            if k and v is not None and str(v).strip():
                                return str(k).strip(), str(v).strip()
        except Exception:
            pass
        return None, None

    # -------------------------------------------------------------
    # 投稿 (Wishes) 関連 API
    # -------------------------------------------------------------
    def get_posts(self, wall_hashid: str, limit: int = 100) -> List[Dict[str, Any]]:
        """全投稿を取得 (重複ID完全排除・無限ページネーション防止・included対応)"""
        if not wall_hashid:
            self.last_posts_fetch_ok = False
            return []

        posts: List[Dict[str, Any]] = []
        seen_ids: Set[str] = set()
        page = 1
        fetch_succeeded = False

        while page <= 10:
            try:
                res = self.request('GET', f"https://padlet.com/api/10/wishes?wall_hashid={wall_hashid}&page={page}&limit={limit}")
                if res.status_code != 200:
                    if page == 1:
                        self.last_posts_fetch_ok = False
                    break

                fetch_succeeded = True
                res_json = res.json()
                data = res_json.get("data", []) if isinstance(res_json, dict) else (res_json if isinstance(res_json, list) else [])
                if not data:
                    break

                user_map: Dict[str, Dict[str, str]] = {}
                if isinstance(res_json, dict):
                    for inc in res_json.get("included", []):
                        if isinstance(inc, dict) and inc.get("type") in ("user", "users"):
                            u_id = str(inc.get("id", "")).strip()
                            u_attrs = inc.get("attributes", {}) if isinstance(inc.get("attributes"), dict) else inc
                            if u_id:
                                user_map[u_id] = {
                                    "username": str(u_attrs.get("username") or "").strip(),
                                    "name": str(u_attrs.get("name") or "").strip(),
                                    "hashid": str(u_attrs.get("hashid") or "").strip()
                                }

                new_in_page = 0
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    pid = str(item.get("id") or "").strip()
                    if not pid or pid in seen_ids:
                        continue
                    seen_ids.add(pid)
                    new_in_page += 1

                    attrs = item.get("attributes") if isinstance(item.get("attributes"), dict) else item
                    subject_val = attrs.get("subject", "")
                    subject_text = str(subject_val or "")

                    body_val = attrs.get("body")
                    content_text = ""
                    if isinstance(body_val, dict):
                        content_text = body_val.get("text", "") or ""
                    elif isinstance(body_val, str):
                        content_text = body_val
                    elif body_val is not None:
                        content_text = str(body_val)

                    attachment_data = attrs.get("attachment")
                    attachment_url = None
                    attachment_caption = ""
                    if isinstance(attachment_data, dict):
                        attachment_url = attachment_data.get("url")
                        attachment_caption = str(attachment_data.get("caption", "") or "")
                    elif isinstance(attachment_data, str):
                        attachment_url = attachment_data

                    if not attachment_url and isinstance(attrs.get("wish_content"), dict):
                        att_props = attrs["wish_content"].get("attachment_props")
                        if isinstance(att_props, dict):
                            attachment_url = att_props.get("url")
                            if not attachment_caption and att_props.get("caption"):
                                attachment_caption = str(att_props.get("caption") or "")

                    if not attachment_caption and attrs.get("caption"):
                        attachment_caption = str(attrs.get("caption") or "")

                    raw_author_id = attrs.get("author_id") or attrs.get("user_id") or attrs.get("creator_id")
                    if not raw_author_id and isinstance(attrs.get("author"), dict):
                        raw_author_id = attrs.get("author", {}).get("id")
                    if not raw_author_id and isinstance(attrs.get("user"), dict):
                        raw_author_id = attrs.get("user", {}).get("id")
                    if not raw_author_id:
                        rels = item.get("relationships") if isinstance(item.get("relationships"), dict) else {}
                        author_rel = rels.get("author", {}).get("data") if isinstance(rels.get("author"), dict) else {}
                        user_rel = rels.get("user", {}).get("data") if isinstance(rels.get("user"), dict) else {}
                        if isinstance(author_rel, dict) and author_rel.get("id"):
                            raw_author_id = author_rel.get("id")
                        elif isinstance(user_rel, dict) and user_rel.get("id"):
                            raw_author_id = user_rel.get("id")

                    raw_author_name = ""
                    if isinstance(attrs.get("author"), dict):
                        raw_author_name = attrs.get("author", {}).get("username") or attrs.get("author", {}).get("name") or ""
                    if not raw_author_name and isinstance(attrs.get("user"), dict):
                        raw_author_name = attrs.get("user", {}).get("username") or attrs.get("user", {}).get("name") or ""

                    if raw_author_id:
                        mapped = user_map.get(str(raw_author_id).strip())
                        if mapped and not raw_author_name:
                            raw_author_name = mapped.get("username") or mapped.get("name") or ""

                    sec_val = attrs.get("wall_section_id") or attrs.get("wallSectionId") or attrs.get("section_id")
                    if not sec_val:
                        rels = item.get("relationships") if isinstance(item.get("relationships"), dict) else {}
                        sec_rel = rels.get("wall_section", {}).get("data") or rels.get("section", {}).get("data")
                        if isinstance(sec_rel, dict) and sec_rel.get("id"):
                            sec_val = sec_rel.get("id")

                    custom_props = attrs.get("custom_properties")

                    posts.append({
                        "id": pid,
                        "subject": subject_text,
                        "content": content_text,
                        "author_id": str(raw_author_id).strip() if (raw_author_id is not None and str(raw_author_id).strip()) else "anonymous",
                        "author_name": str(raw_author_name or "").strip(),
                        "attachment": attachment_url,
                        "attachment_caption": attachment_caption.strip(),
                        "section_id": str(sec_val).strip() if (sec_val is not None and str(sec_val).strip()) else None,
                        "custom_properties": custom_props if isinstance(custom_props, dict) else None,
                        "created_at": attrs.get("created_at")
                    })

                if new_in_page == 0 or len(data) < limit:
                    break
                page += 1
            except Exception:
                if page == 1:
                    fetch_succeeded = False
                break

        self.last_posts_fetch_ok = fetch_succeeded
        return posts

    def _record_created_post_id(self, res: requests.Response):
        """Bot自身が作成した投稿のIDを記録し、自己削除・誤検知を完全防止"""
        try:
            rj = res.json()
            if isinstance(rj, dict):
                data = rj.get("data", rj)
                pid = data.get("id") if isinstance(data, dict) else rj.get("id")
                if pid is not None and str(pid).strip() and str(pid).strip() != "None":
                    with self._created_lock:
                        if len(self.created_post_ids) > 5000:
                            self.created_post_ids.clear()
                        self.created_post_ids.add(str(pid).strip())
        except Exception:
            pass

    def create_post(
        self,
        wall_id: int,
        subject: str = "",
        body: str = "",
        section_id: Optional[str] = None,
        attachment: Optional[str] = None,
        board_hashid: Optional[str] = None,
        custom_key: Optional[str] = None,
        custom_value: Optional[str] = None,
        custom_properties: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        投稿作成 (完全内部API: POST https://padlet.com/api/5/wishes)
        有料APIは完全不使用。カスタム投稿フィールド(custom_properties)にも完全対応。
        """
        wall_id_num = int(wall_id) if str(wall_id).isdigit() else wall_id
        sec_clean = str(section_id).strip() if (section_id is not None and str(section_id).strip() not in ("", "None", "null")) else None
        sec_num = int(sec_clean) if (sec_clean and sec_clean.isdigit()) else sec_clean

        cp_dict: Dict[str, Any] = {}
        if custom_properties and isinstance(custom_properties, dict):
            cp_dict.update(custom_properties)
        if custom_key and str(custom_key).strip():
            cp_dict[str(custom_key).strip()] = str(custom_value or "").strip()

        payload1: Dict[str, Any] = {
            "wallId": wall_id_num,
            "wall_id": wall_id_num,
            "subject": subject or "",
            "body": body or ""
        }
        if sec_num is not None:
            payload1["wallSectionId"] = sec_num
            payload1["wall_section_id"] = sec_num
        if cp_dict:
            payload1["custom_properties"] = cp_dict
        if attachment:
            payload1["attachment"] = attachment
            payload1["wish_content"] = {
                "attachment_props": {"url": attachment},
                "is_processed": False
            }

        url1 = "https://padlet.com/api/5/wishes"
        if sec_num is not None:
            url1 = f"https://padlet.com/api/5/wishes?wall_id={wall_id_num}&wall_section_id={sec_num}"

        try:
            res = self.request('POST', url1, json=payload1, timeout=8)
            if res.status_code in (200, 201):
                self._record_created_post_id(res)
                return True
        except Exception:
            pass

        payload2 = dict(payload1)
        payload2["body"] = {"text": body or ""}
        try:
            res = self.request('POST', "https://padlet.com/api/5/wishes", json=payload2, timeout=8)
            if res.status_code in (200, 201):
                self._record_created_post_id(res)
                return True
        except Exception:
            pass

        try:
            res = self.request('POST', f"https://padlet.com/api/5/wishes?wall_id={wall_id_num}", json=payload1, timeout=8)
            if res.status_code in (200, 201):
                self._record_created_post_id(res)
                return True
        except Exception:
            pass

        return False

    def move_post_to_section(self, post_id: str, section_id: str, wall_id: Optional[int] = None) -> bool:
        """既存投稿を指定セクションへ移動 (セクション再構築時の正常投稿保護用)"""
        if not post_id or not section_id or str(section_id) in ("None", "null", ""):
            return False
        sec_num = int(section_id) if str(section_id).isdigit() else section_id
        payload: Dict[str, Any] = {
            "wall_section_id": sec_num,
            "wallSectionId": sec_num
        }
        if wall_id:
            w_num = int(wall_id) if str(wall_id).isdigit() else wall_id
            payload["wall_id"] = w_num
            payload["wallId"] = w_num

        for ep in (f"https://padlet.com/api/5/wishes/{post_id}", f"https://padlet.com/api/10/wishes/{post_id}"):
            try:
                res = self.request('PATCH', ep, json=payload, timeout=5)
                if res.status_code in (200, 204):
                    return True
            except Exception:
                continue
        return False

    def delete_post(self, post_id: str) -> bool:
        """投稿削除 (マルチエンドポイント対応・404既削除許容)"""
        if not post_id:
            return False
        endpoints = [
            f"https://padlet.com/api/5/wishes/{post_id}",
            f"https://padlet.com/api/10/wishes/{post_id}",
            f"https://padlet.com/api/9/wishes/{post_id}"
        ]
        for ep in endpoints:
            try:
                res = self.request('DELETE', ep, timeout=6)
                if res.status_code in (200, 204, 404):
                    return True
            except Exception:
                continue
        return False

    # -------------------------------------------------------------
    # コメント 関連 API
    # -------------------------------------------------------------
    def get_comments(self, wall_hashid: str) -> List[Dict[str, Any]]:
        """全コメント取得 (重複ID排除・無限ページネーション防止・included対応)"""
        if not wall_hashid:
            self.last_comments_fetch_ok = False
            return []

        comments: List[Dict[str, Any]] = []
        seen_cids: Set[str] = set()
        page = 1
        fetch_succeeded = False

        while page <= 10:
            try:
                res = self.request('GET', f"https://padlet.com/api/9/comments?wall_hashid={wall_hashid}&page={page}&limit=100")
                if res.status_code != 200:
                    if page == 1:
                        self.last_comments_fetch_ok = False
                    break

                fetch_succeeded = True
                res_json = res.json()
                raw_data = res_json.get("data", []) if isinstance(res_json, dict) else (res_json if isinstance(res_json, list) else [])
                if not raw_data:
                    break

                c_user_map: Dict[str, Dict[str, str]] = {}
                if isinstance(res_json, dict):
                    for inc in res_json.get("included", []):
                        if isinstance(inc, dict) and inc.get("type") in ("user", "users"):
                            u_id = str(inc.get("id", "")).strip()
                            u_attrs = inc.get("attributes", {}) if isinstance(inc.get("attributes"), dict) else inc
                            if u_id:
                                c_user_map[u_id] = {
                                    "username": str(u_attrs.get("username") or "").strip(),
                                    "name": str(u_attrs.get("name") or "").strip()
                                }

                new_in_page = 0
                for item in raw_data:
                    if not isinstance(item, dict):
                        continue
                    cid = str(item.get("id", "")).strip()
                    if not cid or cid in seen_cids:
                        continue
                    seen_cids.add(cid)
                    new_in_page += 1

                    attrs = item.get("attributes") if isinstance(item.get("attributes"), dict) else item

                    c_aid = attrs.get("author_id") or attrs.get("user_id") or attrs.get("creator_id")
                    if not c_aid and isinstance(attrs.get("author"), dict):
                        c_aid = attrs.get("author", {}).get("id")
                    if not c_aid and isinstance(attrs.get("user"), dict):
                        c_aid = attrs.get("user", {}).get("id")
                    if not c_aid:
                        rels = item.get("relationships") if isinstance(item.get("relationships"), dict) else {}
                        user_rel = rels.get("user", {}).get("data") if isinstance(rels.get("user"), dict) else {}
                        author_rel = rels.get("author", {}).get("data") if isinstance(rels.get("author"), dict) else {}
                        if isinstance(user_rel, dict) and user_rel.get("id"):
                            c_aid = user_rel.get("id")
                        elif isinstance(author_rel, dict) and author_rel.get("id"):
                            c_aid = author_rel.get("id")

                    c_name = ""
                    if isinstance(attrs.get("author"), dict):
                        c_name = attrs.get("author", {}).get("username") or attrs.get("author", {}).get("name") or ""
                    if not c_name and isinstance(attrs.get("user"), dict):
                        c_name = attrs.get("user", {}).get("username") or attrs.get("user", {}).get("name") or ""

                    if c_aid and not c_name:
                        c_mapped = c_user_map.get(str(c_aid).strip())
                        if c_mapped:
                            c_name = c_mapped.get("username") or c_mapped.get("name") or ""

                    body_val = attrs.get("body") or attrs.get("value") or ""
                    body_text = body_val.get("text", "") if isinstance(body_val, dict) else str(body_val or "")

                    wish_id = attrs.get("wish_id") or attrs.get("wall_wish_id")
                    if not wish_id:
                        rels = item.get("relationships") if isinstance(item.get("relationships"), dict) else {}
                        wish_rel = rels.get("wish", {}).get("data") if isinstance(rels.get("wish"), dict) else {}
                        if isinstance(wish_rel, dict):
                            wish_id = wish_rel.get("id")

                    comments.append({
                        "id": cid,
                        "author_id": str(c_aid).strip() if (c_aid is not None and str(c_aid).strip()) else "anonymous",
                        "author_name": str(c_name or "").strip(),
                        "content": str(body_text),
                        "wish_id": str(wish_id).strip() if wish_id else None,
                        "created_at": attrs.get("created_at")
                    })

                if new_in_page == 0 or len(raw_data) < 100:
                    break
                page += 1
            except Exception:
                if page == 1:
                    fetch_succeeded = False
                break

        self.last_comments_fetch_ok = fetch_succeeded
        return comments

    def delete_comment(self, comment_id: str) -> bool:
        """コメント削除 (全APIバージョン対応)"""
        if not comment_id:
            return False
        endpoints = [
            f"https://padlet.com/api/8/comments/{comment_id}",
            f"https://padlet.com/api/9/comments/{comment_id}",
            f"https://padlet.com/api/10/comments/{comment_id}",
            f"https://padlet.com/api/5/comments/{comment_id}"
        ]
        for ep in endpoints:
            try:
                res = self.request('DELETE', ep, timeout=5)
                if res.status_code in (200, 204, 404):
                    return True
            except Exception:
                continue
        return False

    # -------------------------------------------------------------
    # セクション 関連 API
    # -------------------------------------------------------------
    @staticmethod
    def _safe_section_sort_key(sec: Dict[str, Any]) -> tuple[int, float]:
        idx = sec.get("sort_index")
        if idx is None:
            return (1, 0.0)
        try:
            return (0, float(idx))
        except (ValueError, TypeError):
            return (0, 0.0)

    def get_sections(self, wall_id: int) -> List[Dict[str, Any]]:
        """セクション一覧取得 (型安全なソート・フォールバック対応)"""
        if not wall_id:
            self.last_sections_fetch_ok = False
            return []

        endpoints = [
            f"https://padlet.com/api/5/wall_sections?wall_id={wall_id}",
            f"https://padlet.com/api/10/wall_sections?wall_id={wall_id}"
        ]
        for ep in endpoints:
            try:
                res = self.request('GET', ep)
                if res.status_code != 200:
                    continue
                rj = res.json()
                raw_list = rj.get("data", []) if isinstance(rj, dict) else (rj if isinstance(rj, list) else [])
                sections: List[Dict[str, Any]] = []
                seen_sids: Set[str] = set()
                for s in raw_list:
                    if not isinstance(s, dict):
                        continue
                    sid = str(s.get("id") or "").strip()
                    if not sid or sid == "None" or sid in seen_sids:
                        continue
                    seen_sids.add(sid)
                    attrs = s.get("attributes") if isinstance(s.get("attributes"), dict) else s
                    sections.append({
                        "id": sid,
                        "hashid": attrs.get("hashid") or s.get("hashid"),
                        "title": str(attrs.get("title") or attrs.get("name") or s.get("title") or "名称未設定"),
                        "sort_index": attrs.get("sort_index") if "sort_index" in attrs else s.get("sort_index")
                    })
                sections.sort(key=self._safe_section_sort_key)
                self.last_sections_fetch_ok = True
                return sections
            except Exception:
                continue

        self.last_sections_fetch_ok = False
        return []

    def create_section(self, wall_id: int, title: str, sort_index: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """新規セクション作成 (ID検証・フォールバック対応)"""
        wall_id_num = int(wall_id) if str(wall_id).isdigit() else wall_id
        s_idx = float(sort_index) if sort_index is not None else time.time()
        payload = {
            "wall_id": wall_id_num,
            "wallId": wall_id_num,
            "title": title,
            "sort_index": s_idx,
            "gap_size": None,
            "color": None
        }
        for ep in ("https://padlet.com/api/5/wall_sections", f"https://padlet.com/api/5/wall_sections?wall_id={wall_id_num}"):
            try:
                res = self.request('POST', ep, json=payload)
                if res.status_code in (200, 201):
                    rj = res.json()
                    if isinstance(rj, dict):
                        data = rj.get("data") if isinstance(rj.get("data"), dict) else rj
                        sec_id = data.get("id") or rj.get("id")
                        if sec_id is not None and str(sec_id).strip() and str(sec_id).strip() != "None":
                            return {
                                "id": str(sec_id).strip(),
                                "title": title
                            }
            except Exception:
                continue
        return None

    def delete_section(self, section_id: str, wall_id: Optional[int] = None) -> bool:
        """セクション削除 (全エンドポイント・全クエリ対応)"""
        if not section_id or str(section_id) in ("None", "null", ""):
            return False
        urls = [
            f"https://padlet.com/api/5/wall_sections/{section_id}",
            f"https://padlet.com/api/5/wall_sections/{section_id}?soft_delete=true",
            f"https://padlet.com/api/8/wall_sections/{section_id}",
            f"https://padlet.com/api/10/wall_sections/{section_id}"
        ]
        if wall_id:
            urls.append(f"https://padlet.com/api/5/wall_sections/{section_id}?wall_id={wall_id}")
            urls.append(f"https://padlet.com/api/8/walls/{wall_id}/wall_sections/{section_id}")
            urls.append(f"https://padlet.com/api/10/walls/{wall_id}/wall_sections/{section_id}")
        for u in urls:
            try:
                res = self.request('DELETE', u, timeout=5)
                if res.status_code in (200, 204, 404):
                    return True
            except Exception:
                continue
        return False

    # -------------------------------------------------------------
    # コラボレーター / 権限 関連 API
    # -------------------------------------------------------------
    def get_collaborators(self, wall_hashid: str, wall_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """コラボレーター一覧取得 (user_idとレコードIDの正確な分離・ネストuser抽出・included統合)"""
        collabs: List[Dict[str, Any]] = []
        by_uid: Dict[str, Dict[str, Any]] = {}

        def _add_collab(raw_uid, record_id="", hashid="", name="", username="", role=""):
            uid = str(raw_uid).strip() if (raw_uid is not None and str(raw_uid).strip() not in ("", "None", "null")) else ""
            if not uid or uid == "anonymous":
                return
            rec_id = str(record_id).strip() if (record_id is not None and str(record_id).strip() not in ("", "None", "null")) else ""
            hid = str(hashid or "").strip()
            uname = str(username or "").strip()
            disp_name = str(name or "").strip()
            role_str = str(role or "").strip().lower()

            if uid in by_uid:
                existing = by_uid[uid]
                if rec_id and not existing.get("collab_id"):
                    existing["collab_id"] = rec_id
                if hid and not existing.get("hashid"):
                    existing["hashid"] = hid
                if uname and not existing.get("username"):
                    existing["username"] = uname
                if disp_name and (not existing.get("name") or existing.get("name") == existing.get("user_id")):
                    existing["name"] = disp_name
                if role_str and not existing.get("role"):
                    existing["role"] = role_str
            else:
                entry = {
                    "user_id": uid,
                    "collab_id": rec_id if rec_id != uid else "",
                    "hashid": hid,
                    "name": disp_name or uname or uid,
                    "username": uname,
                    "role": role_str
                }
                by_uid[uid] = entry
                collabs.append(entry)

        def _parse_collab_items(rj: Any):
            if not isinstance(rj, dict):
                return
            inc_map: Dict[str, Dict[str, Any]] = {}
            for inc in rj.get("included", []):
                if isinstance(inc, dict) and inc.get("type") in ("user", "users"):
                    iid = str(inc.get("id", "")).strip()
                    iattrs = inc.get("attributes", {}) if isinstance(inc.get("attributes"), dict) else inc
                    if iid:
                        inc_map[iid] = iattrs

            data_node = rj.get("data", [])
            items = []
            if isinstance(data_node, dict):
                attrs_node = data_node.get("attributes", {}) if isinstance(data_node.get("attributes"), dict) else data_node
                for key in ("collaborators", "user_collaborators", "role_assignments"):
                    if isinstance(attrs_node.get(key), list):
                        items.extend(attrs_node.get(key))
            elif isinstance(data_node, list):
                items.extend(data_node)

            for c in items:
                if not isinstance(c, dict):
                    continue
                attrs = c.get("attributes") if isinstance(c.get("attributes"), dict) else c
                user_obj = attrs.get("user") or c.get("user")
                if not isinstance(user_obj, dict):
                    user_obj = {}

                rels = c.get("relationships") if isinstance(c.get("relationships"), dict) else {}
                user_rel = rels.get("user", {}).get("data") if isinstance(rels.get("user"), dict) else {}
                if not isinstance(user_rel, dict):
                    user_rel = {}

                real_uid = (
                    attrs.get("user_id")
                    or attrs.get("userId")
                    or c.get("user_id")
                    or c.get("userId")
                    or user_obj.get("id")
                    or user_rel.get("id")
                    or c.get("id")
                )
                record_id = c.get("id")
                uinfo = inc_map.get(str(real_uid).strip(), {}) if real_uid is not None else {}

                uname = (
                    user_obj.get("username")
                    or attrs.get("username")
                    or c.get("username")
                    or uinfo.get("username")
                    or ""
                )
                name = (
                    user_obj.get("name")
                    or attrs.get("name")
                    or c.get("name")
                    or uinfo.get("name")
                    or ""
                )
                hid = (
                    user_obj.get("hashid")
                    or attrs.get("hashid")
                    or c.get("hashid")
                    or uinfo.get("hashid")
                    or ""
                )
                role = attrs.get("role") or c.get("role") or ""
                _add_collab(real_uid, record_id=record_id, hashid=hid, name=name, username=uname, role=role)

        if wall_hashid:
            try:
                res = self.request('GET', f"https://padlet.com/api/10/walls/{wall_hashid}/access-settings")
                if res.status_code == 200:
                    _parse_collab_items(res.json())
            except Exception:
                pass

        if wall_id:
            for ep in (
                f"https://padlet.com/api/8/walls/{wall_id}/collaborators",
                f"https://padlet.com/api/8/walls/{wall_id}/user-collaborators",
                f"https://padlet.com/api/10/walls/{wall_id}/user-collaborators"
            ):
                try:
                    res = self.request('GET', ep)
                    if res.status_code == 200:
                        _parse_collab_items(res.json())
                except Exception:
                    pass

        return collabs

    def change_user_role(
        self,
        wall_id: int,
        user_id: str,
        role: str = "reader",
        board_hashid: Optional[str] = None,
        collab_id: Optional[str] = None
    ) -> bool:
        """
        指定ユーザーの権限(role: reader / writer 等)を確実に変更・固定する。
        既存コラボレーターの権限変更(PATCH/PUT)および未登録ユーザーの追加(POST)、
        さらにPATCH非対応時の再登録フォールバックに対応。
        """
        if not user_id or user_id == "anonymous":
            return False

        uid_str = str(user_id).strip()
        target_ids = [uid_str]
        if collab_id and str(collab_id).strip() and str(collab_id).strip() != uid_str:
            target_ids.insert(0, str(collab_id).strip())

        # 1. 既存コラボレーターの権限変更 (PATCH)
        patch_urls = []
        for tid in target_ids:
            patch_urls.append(f"https://padlet.com/api/8/walls/{wall_id}/user-collaborators/{tid}")
            patch_urls.append(f"https://padlet.com/api/10/walls/{wall_id}/user-collaborators/{tid}")
            patch_urls.append(f"https://padlet.com/api/8/walls/{wall_id}/collaborators/{tid}")
            if board_hashid:
                patch_urls.append(f"https://padlet.com/api/8/walls/{board_hashid}/user-collaborators/{tid}")
                patch_urls.append(f"https://padlet.com/api/10/walls/{board_hashid}/user-collaborators/{tid}")
                patch_urls.append(f"https://padlet.com/api/10/walls/{board_hashid}/collaborators/{tid}")

        patch_payloads = [
            {"role": role},
            {"data": {"attributes": {"role": role}}}
        ]
        for url in patch_urls:
            for payload in patch_payloads:
                try:
                    res = self.request('PATCH', url, json=payload, timeout=5)
                    if res.status_code in (200, 204):
                        return True
                except Exception:
                    pass

        # 2. まだコラボレーターにいない場合は、指定role(reader/writer等)としてコラボレーターに追加 (POST)
        post_urls = [
            f"https://padlet.com/api/8/walls/{wall_id}/user-collaborators",
            f"https://padlet.com/api/10/walls/{wall_id}/user-collaborators"
        ]
        if board_hashid:
            post_urls.append(f"https://padlet.com/api/10/walls/{board_hashid}/user-collaborators")

        uid_val: Any = int(uid_str) if uid_str.isdigit() else uid_str
        post_payloads = [
            {"user_id": uid_val, "role": role},
            {"userId": uid_val, "role": role},
            {"user_id": uid_str, "role": role},
            {"data": {"attributes": {"user_id": uid_val, "role": role}}}
        ]
        for url in post_urls:
            for p in post_payloads:
                try:
                    res = self.request('POST', url, json=p, timeout=5)
                    if res.status_code in (200, 201, 204):
                        return True
                except Exception:
                    pass

        # 3. 既存コラボレーターに対してPATCH/POSTが409/422等で拒否された場合、一旦DELETEしてから指定ロールで即再登録
        deleted_existing = False
        for tid in target_ids:
            for del_url in (
                f"https://padlet.com/api/8/walls/{wall_id}/user-collaborators/{tid}",
                f"https://padlet.com/api/10/walls/{wall_id}/user-collaborators/{tid}"
            ):
                try:
                    dres = self.request('DELETE', del_url, timeout=4)
                    if dres.status_code in (200, 204):
                        deleted_existing = True
                        break
                except Exception:
                    pass
            if deleted_existing:
                break

        if deleted_existing:
            for url in post_urls:
                for p in post_payloads:
                    try:
                        res = self.request('POST', url, json=p, timeout=5)
                        if res.status_code in (200, 201, 204):
                            return True
                    except Exception:
                        pass

        return False

    def change_visitor_role(self, wall_hashid: str, role: str = "reader", wall_id: Optional[int] = None) -> bool:
        """訪問者のデフォルト権限変更 (none/reader/commenter/writer対応・マルチエンドポイント)"""
        role_values: List[Any] = [role]
        if role == "none":
            role_values.append(None)

        endpoints = []
        if wall_hashid:
            endpoints.append(f"https://padlet.com/api/10/walls/{wall_hashid}/access-settings")
        if wall_id:
            endpoints.append(f"https://padlet.com/api/10/walls/{wall_id}/access-settings")
            endpoints.append(f"https://padlet.com/api/8/walls/{wall_id}/access-settings")

        for r_val in role_values:
            payloads = [
                {"visitorRole": r_val},
                {"data": {"attributes": {"visitorRole": r_val}}},
                {"visitor_role": r_val}
            ]
            for ep in endpoints:
                for p in payloads:
                    try:
                        res = self.request('PATCH', ep, json=p, timeout=5)
                        if res.status_code in (200, 204):
                            return True
                    except Exception:
                        continue
        return False
