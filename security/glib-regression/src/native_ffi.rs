// SPDX-License-Identifier: Apache-2.0
// Reviewed from styayur/vextessera 2bab4e50ac16e4b684de8cf700f196ede36408f1.
// Full terms: ../LICENSE-APACHE-2.0. URI credentials below are synthetic parser fixtures.
pub fn verify() -> Result<(), Box<dyn std::error::Error>> {
    let (_, charset) = glib::charset();
    assert!(charset.is_some_and(|value| !value.is_empty()));
    let (_, filename_charsets) = glib::filename_charsets();
    assert!(!filename_charsets.is_empty());
    assert!(filename_charsets.iter().all(|value| !value.is_empty()));
    let (scheme, userinfo, host, port, path, query, fragment) = glib::Uri::split(
        "https://example.org:8443/path?q=1#part",
        glib::UriFlags::empty(),
    )?;
    assert_eq!(scheme.as_ref().map(|value| value.as_str()), Some("https"));
    assert!(userinfo.is_none());
    assert_eq!(
        host.as_ref().map(|value| value.as_str()),
        Some("example.org")
    );
    assert_eq!(port, 8443);
    assert_eq!(path.as_str(), "/path");
    assert_eq!(query.as_ref().map(|value| value.as_str()), Some("q=1"));
    assert_eq!(fragment.as_ref().map(|value| value.as_str()), Some("part"));
    let (scheme, userinfo, host, port, path, query, fragment) =
        glib::Uri::split("relative", glib::UriFlags::empty())?;
    assert!(scheme.is_none() && userinfo.is_none() && host.is_none());
    assert_eq!(port, -1);
    assert_eq!(path.as_str(), "relative");
    assert!(query.is_none() && fragment.is_none());
    let (_, _, password, auth, _, _, _, _, _) = glib::Uri::split_with_user(
        "https://name:fixture;meta@example.org/path",
        glib::UriFlags::HAS_PASSWORD | glib::UriFlags::HAS_AUTH_PARAMS,
    )?;
    assert!(password.as_ref().map(|value| value.as_str()) == Some("fixture"));
    assert!(auth.as_ref().map(|value| value.as_str()) == Some("meta"));
    let (scheme, host, port) =
        glib::Uri::split_network("https://example.org:8443/path", glib::UriFlags::empty())?;
    assert_eq!(scheme.as_ref().map(|value| value.as_str()), Some("https"));
    assert_eq!(
        host.as_ref().map(|value| value.as_str()),
        Some("example.org")
    );
    assert_eq!(port, 8443);
    let (scheme, user, password, auth, host, port, path, query, fragment) =
        glib::Uri::split_with_user("https://name@example.org/path", glib::UriFlags::empty())?;
    assert_eq!(scheme.as_ref().map(|value| value.as_str()), Some("https"));
    assert_eq!(user.as_ref().map(|value| value.as_str()), Some("name"));
    assert!(password.is_none() && auth.is_none());
    assert_eq!(
        host.as_ref().map(|value| value.as_str()),
        Some("example.org")
    );
    assert_eq!(port, -1);
    assert_eq!(path.as_str(), "/path");
    assert!(query.is_none() && fragment.is_none());
    // Exercise the actual full_path gchar* -> owned GString -> PathBuf chain
    // exposed by the full-main SARIF, with an owned Unicode filename fixture.
    let directory = tempfile::tempdir()?;
    let file_name = "owned-中文.conf";
    let expected_path = directory.path().join(file_name);
    std::fs::write(&expected_path, "[group]\nnumber=42\n")?;
    let disk_key_file = glib::KeyFile::new();
    let full_path = disk_key_file.load_from_dirs(
        file_name,
        &[directory.path()],
        glib::KeyFileFlags::empty(),
    )?;
    assert_eq!(full_path, expected_path);
    assert_eq!(disk_key_file.integer("group", "number")?, 42);
    assert!(disk_key_file
        .load_from_dirs(
            "missing-file.conf",
            &[directory.path()],
            glib::KeyFileFlags::empty(),
        )
        .is_err());
    let input = "Unicode 中文".as_bytes();
    let (converted, bytes_read) = glib::convert(input, "UTF-8", "UTF-8")?;
    assert_eq!(&*converted, input);
    assert_eq!(bytes_read, input.len());
    assert!(matches!(
        glib::convert(&[0xff], "UTF-8", "UTF-8"),
        Err(glib::CvtError::IllegalSequence { offset: 0, .. })
    ));
    let key_file = glib::KeyFile::new();
    assert!(key_file
        .load_from_data("invalid data", glib::KeyFileFlags::empty())
        .is_err());
    key_file.load_from_data(
        "[group]\nname=中文\nnumber=42\n",
        glib::KeyFileFlags::empty(),
    )?;
    assert_eq!(key_file.string("group", "name")?.as_str(), "中文");
    assert_eq!(key_file.integer("group", "number")?, 42);
    assert!(key_file.string("group", "missing").is_err());
    assert!(key_file.integer("group", "name").is_err());
    assert!(glib::shell_parse_argv("'unterminated").is_err());
    assert!(glib::Uri::parse("not a URI", glib::UriFlags::empty()).is_err());
    assert!(glib::Uri::parse("https://example.org/path", glib::UriFlags::empty()).is_ok());
    assert!(glib::Variant::parse(None, "not a variant").is_err());
    assert_eq!(
        glib::Variant::parse(None, "'中文'")?
            .get::<String>()
            .as_deref(),
        Some("中文")
    );
    assert!(glib::uuid_string_is_valid(
        "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
    ));
    assert!(!glib::uuid_string_is_valid("not-a-uuid"));
    if let Some(charset) = glib::console_charset() {
        assert!(!charset.is_empty());
    }
    let path = std::path::PathBuf::from("/tmp/vextessera unicode 中文.txt");
    let uri = glib::filename_to_uri(&path, None)?;
    let (round_trip, hostname) = glib::filename_from_uri(&uri)?;
    assert_eq!(round_trip, path);
    assert!(hostname.is_none());
    assert!(glib::filename_from_uri("not-a-file-uri").is_err());
    assert!(glib::filename_to_uri("relative-path", None).is_err());
    let missing = std::env::temp_dir().join(format!(
        "vextessera-glib-regression-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    assert!(!missing.exists());
    let file = missing.join("uncreated-parent").join("test.txt");
    assert!(glib::file_set_contents(&file, b"test").is_err());
    assert!(glib::file_set_contents_full(
        &file,
        b"test",
        glib::FileSetContentsFlags::empty(),
        0o600
    )
    .is_err());
    assert!(!missing.exists());
    Ok(())
}
