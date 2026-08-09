"""HTTP client wrapping a Juice Shop session (auth header + cookie)."""
import requests


class JuiceShopClient:
    def __init__(self, base_url: str = "http://localhost:3000"):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.token: str | None = None

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def register(self, email: str, password: str, security_question_id: int = 1,
                 security_answer: str = "n/a") -> requests.Response:
        payload = {
            "email": email,
            "password": password,
            "passwordRepeat": password,
            "securityQuestion": {"id": security_question_id},
            "securityAnswer": security_answer,
        }
        return self.session.post(self._url("/api/Users"), json=payload)

    def login(self, email: str, password: str) -> requests.Response:
        resp = self.session.post(
            self._url("/rest/user/login"),
            json={"email": email, "password": password},
        )
        if resp.status_code == 401:
            try:
                data = resp.json()
            except ValueError:
                data = {}
            if data.get("status") == "totp_token_required":
                return resp
            raise RuntimeError(f"login failed for {email!r}: {resp.status_code} {resp.text}")
        resp.raise_for_status()
        token = resp.json()["authentication"]["token"]
        self._set_token(token)
        return resp

    def verify_2fa(self, tmp_token: str, totp_token: str) -> requests.Response:
        resp = self.session.post(
            self._url("/rest/2fa/verify"),
            json={"tmpToken": tmp_token, "totpToken": totp_token},
        )
        resp.raise_for_status()
        token = resp.json()["authentication"]["token"]
        self._set_token(token)
        return resp

    def _set_token(self, token: str) -> None:
        self.token = token
        self.session.headers["Authorization"] = f"Bearer {token}"
        self.session.cookies.set("token", token)

    def get(self, path: str, **kwargs) -> requests.Response:
        return self.session.get(self._url(path), **kwargs)

    def post(self, path: str, **kwargs) -> requests.Response:
        return self.session.post(self._url(path), **kwargs)

    def put(self, path: str, **kwargs) -> requests.Response:
        return self.session.put(self._url(path), **kwargs)

    def patch(self, path: str, **kwargs) -> requests.Response:
        return self.session.patch(self._url(path), **kwargs)
