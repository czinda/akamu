use crate::db::schema::CrossCertRow;
use crate::error::AcmeError;

pub async fn insert(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    row: &CrossCertRow,
) -> Result<(), AcmeError> {
    super::query(
        "INSERT INTO cross_certs
         (id, issuer_ca_id, subject_ca_id, subject_dn, subject_spki,
          cross_cert_der, cross_cert_pem, not_before, not_after, serial_number, created)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&row.id)
    .bind(&row.issuer_ca_id)
    .bind(&row.subject_ca_id)
    .bind(&row.subject_dn)
    .bind(&row.subject_spki)
    .bind(&row.cross_cert_der)
    .bind(&row.cross_cert_pem)
    .bind(row.not_before)
    .bind(row.not_after)
    .bind(&row.serial_number)
    .bind(row.created)
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn get_by_id(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
) -> Result<Option<CrossCertRow>, AcmeError> {
    let row = super::query_as::<CrossCertRow>(
        "SELECT id, issuer_ca_id, subject_ca_id, subject_dn, subject_spki,
         cross_cert_der, cross_cert_pem, not_before, not_after, serial_number, created
         FROM cross_certs WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// List cross-certs where this CA is the subject (i.e. cross-certs issued FOR this CA).
pub async fn list_by_subject_ca(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    subject_ca_id: &str,
) -> Result<Vec<CrossCertRow>, AcmeError> {
    let rows = super::query_as::<CrossCertRow>(
        "SELECT id, issuer_ca_id, subject_ca_id, subject_dn, subject_spki,
         cross_cert_der, cross_cert_pem, not_before, not_after, serial_number, created
         FROM cross_certs WHERE subject_ca_id = ?
         ORDER BY created DESC LIMIT 100",
    )
    .bind(subject_ca_id)
    .fetch_all(executor)
    .await?;
    Ok(rows)
}

/// List cross-certs where this CA is the issuer (i.e. cross-certs issued BY this CA).
pub async fn list_by_issuer_ca(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    issuer_ca_id: &str,
) -> Result<Vec<CrossCertRow>, AcmeError> {
    let rows = super::query_as::<CrossCertRow>(
        "SELECT id, issuer_ca_id, subject_ca_id, subject_dn, subject_spki,
         cross_cert_der, cross_cert_pem, not_before, not_after, serial_number, created
         FROM cross_certs WHERE issuer_ca_id = ?
         ORDER BY created DESC LIMIT 100",
    )
    .bind(issuer_ca_id)
    .fetch_all(executor)
    .await?;
    Ok(rows)
}

/// List all cross-certs with optional CA filters.
///
/// Both filters are optional; when `None`, that dimension is not filtered.
pub async fn list(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    issuer_ca_id: Option<&str>,
    subject_ca_id: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<CrossCertRow>, AcmeError> {
    let mut qb = super::DynQueryBuilder::new(
        "SELECT id, issuer_ca_id, subject_ca_id, subject_dn, subject_spki,
         cross_cert_der, cross_cert_pem, not_before, not_after, serial_number, created
         FROM cross_certs WHERE 1=1",
    );

    if let Some(issuer) = issuer_ca_id {
        qb.push(" AND issuer_ca_id = ");
        qb.push_bind(issuer);
    }
    if let Some(subject) = subject_ca_id {
        qb.push(" AND subject_ca_id = ");
        qb.push_bind(subject);
    }
    qb.push(" ORDER BY created DESC LIMIT ");
    qb.push_bind(limit);
    qb.push(" OFFSET ");
    qb.push_bind(offset);

    let rows = qb.fetch_all::<_, CrossCertRow>(executor).await?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn sample_cross_cert(id: &str, issuer: &str, subject: Option<&str>) -> CrossCertRow {
        CrossCertRow {
            id: id.to_string(),
            issuer_ca_id: issuer.to_string(),
            subject_ca_id: subject.map(str::to_string),
            subject_dn: "CN=Test CA".to_string(),
            subject_spki: vec![0x30, 0x82, 0x01, 0x22], // fake DER
            cross_cert_der: vec![0x30, 0x82, 0x02, 0x00], // fake DER
            cross_cert_pem: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
                .to_string(),
            not_before: 1_700_000_000,
            not_after: 1_800_000_000,
            serial_number: format!("{id}abcdef"),
            created: 1_700_000_000,
        }
    }

    async fn open_db() -> db::Db {
        db::install_drivers();
        db::open("sqlite::memory:", 1, false).await.unwrap()
    }

    #[tokio::test]
    async fn insert_and_get_by_id() {
        let pool = open_db().await;
        let row = sample_cross_cert("xc-001", "rsa", Some("ml-dsa"));
        insert(&pool, &row).await.unwrap();

        let got = get_by_id(&pool, "xc-001").await.unwrap().unwrap();
        assert_eq!(got.id, "xc-001");
        assert_eq!(got.issuer_ca_id, "rsa");
        assert_eq!(got.subject_ca_id.as_deref(), Some("ml-dsa"));
        assert_eq!(got.subject_dn, "CN=Test CA");
        assert_eq!(got.subject_spki, row.subject_spki);
        assert_eq!(got.cross_cert_der, row.cross_cert_der);
        assert_eq!(got.cross_cert_pem, row.cross_cert_pem);
        assert_eq!(got.not_before, row.not_before);
        assert_eq!(got.not_after, row.not_after);
        assert_eq!(got.serial_number, row.serial_number);
        assert_eq!(got.created, row.created);
    }

    #[tokio::test]
    async fn get_by_id_missing_returns_none() {
        let pool = open_db().await;
        let got = get_by_id(&pool, "nonexistent").await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn list_by_subject_ca_filters_correctly() {
        let pool = open_db().await;
        insert(&pool, &sample_cross_cert("xc-a1", "rsa", Some("ml-dsa")))
            .await
            .unwrap();
        insert(&pool, &sample_cross_cert("xc-a2", "rsa", Some("ml-dsa")))
            .await
            .unwrap();
        insert(&pool, &sample_cross_cert("xc-b1", "ml-dsa", Some("ec")))
            .await
            .unwrap();

        let ml_dsa_certs = list_by_subject_ca(&pool, "ml-dsa").await.unwrap();
        assert_eq!(ml_dsa_certs.len(), 2);
        assert!(ml_dsa_certs
            .iter()
            .all(|r| r.subject_ca_id.as_deref() == Some("ml-dsa")));

        let ec_certs = list_by_subject_ca(&pool, "ec").await.unwrap();
        assert_eq!(ec_certs.len(), 1);

        let none_certs = list_by_subject_ca(&pool, "unknown").await.unwrap();
        assert!(none_certs.is_empty());
    }

    #[tokio::test]
    async fn list_by_issuer_ca_filters_correctly() {
        let pool = open_db().await;
        insert(&pool, &sample_cross_cert("xc-r1", "rsa", Some("ml-dsa")))
            .await
            .unwrap();
        insert(&pool, &sample_cross_cert("xc-r2", "rsa", Some("ec")))
            .await
            .unwrap();
        insert(&pool, &sample_cross_cert("xc-m1", "ml-dsa", Some("rsa")))
            .await
            .unwrap();

        let rsa_issued = list_by_issuer_ca(&pool, "rsa").await.unwrap();
        assert_eq!(rsa_issued.len(), 2);

        let ml_dsa_issued = list_by_issuer_ca(&pool, "ml-dsa").await.unwrap();
        assert_eq!(ml_dsa_issued.len(), 1);
    }

    #[tokio::test]
    async fn list_with_filters() {
        let pool = open_db().await;
        insert(&pool, &sample_cross_cert("xc-f1", "rsa", Some("ml-dsa")))
            .await
            .unwrap();
        insert(&pool, &sample_cross_cert("xc-f2", "rsa", Some("ec")))
            .await
            .unwrap();
        insert(&pool, &sample_cross_cert("xc-f3", "ml-dsa", Some("rsa")))
            .await
            .unwrap();

        // Both filters
        let rows = list(&pool, Some("rsa"), Some("ml-dsa"), 100, 0)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "xc-f1");

        // Issuer only
        let rows = list(&pool, Some("rsa"), None, 100, 0).await.unwrap();
        assert_eq!(rows.len(), 2);

        // No filters
        let rows = list(&pool, None, None, 100, 0).await.unwrap();
        assert_eq!(rows.len(), 3);

        // Pagination
        let rows = list(&pool, None, None, 2, 0).await.unwrap();
        assert_eq!(rows.len(), 2);
        let rows = list(&pool, None, None, 2, 2).await.unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn external_ca_subject_is_null() {
        let pool = open_db().await;
        // subject_ca_id = None means external CA
        let row = sample_cross_cert("xc-ext", "rsa", None);
        insert(&pool, &row).await.unwrap();

        let got = get_by_id(&pool, "xc-ext").await.unwrap().unwrap();
        assert!(got.subject_ca_id.is_none());
    }
}

/// Count cross-certificates matching the same filters as [`list`], without LIMIT/OFFSET.
pub async fn count_list(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    issuer_ca_id: Option<&str>,
    subject_ca_id: Option<&str>,
) -> Result<i64, crate::error::AcmeError> {
    let mut qb = super::DynQueryBuilder::new("SELECT COUNT(*) FROM cross_certs WHERE 1=1");
    if let Some(issuer) = issuer_ca_id {
        qb.push(" AND issuer_ca_id = ");
        qb.push_bind(issuer);
    }
    if let Some(subject) = subject_ca_id {
        qb.push(" AND subject_ca_id = ");
        qb.push_bind(subject);
    }
    let row: (i64,) = qb.fetch_one(executor).await?;
    Ok(row.0)
}
