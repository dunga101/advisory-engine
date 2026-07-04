from scripts import render_env


def test_service_keys_give_each_service_a_distinct_database_url_vault_key():
    """Architecture review item 2: collectors/publisher/review must never
    resolve DATABASE_URL from the same vault key — that's exactly the
    byte-identical-secret setup this item exists to break."""
    vault_keys_for_database_url = {
        service: mapping["DATABASE_URL"] for service, mapping in render_env.SERVICE_KEYS.items()
    }
    assert len(set(vault_keys_for_database_url.values())) == len(vault_keys_for_database_url)


def test_review_service_never_holds_github_token_or_cisco_credentials():
    review_vault_keys = set(render_env.SERVICE_KEYS["review"].values())
    assert "GITHUB_PUSH_TOKEN" not in review_vault_keys
    assert "CISCO_CLIENT_ID" not in review_vault_keys
    assert "CISCO_CLIENT_SECRET" not in review_vault_keys


def test_main_writes_each_service_env_file_from_its_own_vault_key(tmp_path, monkeypatch):
    monkeypatch.setattr(render_env, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(
        render_env,
        "_decrypt_secrets",
        lambda: {
            "DATABASE_URL": "postgresql://collectors-role@db-01/advisory_engine",
            "DATABASE_URL_PUBLISHER": "postgresql://publisher-role@db-01/advisory_engine",
            "DATABASE_URL_REVIEW": "postgresql://review-role@db-01/advisory_engine",
            "CISCO_CLIENT_ID": "cid",
            "CISCO_CLIENT_SECRET": "csecret",
            "GITHUB_PUSH_TOKEN": "ghp_faketoken",
        },
    )

    render_env.main()

    publisher_env = (tmp_path / ".env.publisher").read_text()
    review_env = (tmp_path / ".env.review").read_text()
    collectors_env = (tmp_path / ".env.collectors").read_text()

    assert "publisher-role" in publisher_env
    assert "review-role" not in publisher_env
    assert "GITHUB_PUSH_TOKEN" in publisher_env

    assert "review-role" in review_env
    assert "collectors-role" not in review_env
    assert "publisher-role" not in review_env
    assert "GITHUB_PUSH_TOKEN" not in review_env
    assert "CISCO_CLIENT_ID" not in review_env

    assert "collectors-role" in collectors_env
    assert "review-role" not in collectors_env
