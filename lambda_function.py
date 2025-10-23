# lambda_function.py
"""
Complete AWS Lambda entrypoint for AD automation.

What this file does:
- Reads Google Sheets ranges (Exit & Revoked Resignation) using OAuth credentials stored
  in AWS Secrets Manager.
- Saves a snapshot Excel copy of the sheets to S3 for audit.
- Computes the latest unique row per employee ID and determines Exit Status.
- Notifies via SNS about any rows dropped due to invalid/unstructured dates.
- Connects to Active Directory via the ADAP class and enables/disables accounts
  according to the Exit Status.
- Publishes a summary SNS message at the end listing enabled/disabled/invalid users.

SECURITY NOTES:
- Do NOT store secrets in this file. Use AWS Secrets Manager and environment variables.
- Deploy binary dependencies (ldap3, pandas, openpyxl) as a Lambda layer or package.
"""

import os
import json
import logging
import time
from datetime import datetime
import boto3
import requests
import pandas as pd

# Import your AD helper. Ensure file name and class name match your repo.
# from Ad import ADAP
# If your file name is Ad.py and class ADAP, the import above will work.
try:
    from ad import ADAP
except Exception:
    # If import fails during local linting, provide a helpful warning (Lambda will fail if missing)
    ADAP = None

# Configure logger
logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# Environment / configuration variables (set these in Lambda console / SAM / Terraform)
AD_SECRET_NAME = os.environ.get("AD_SECRET_NAME", "arn:aws:secretsmanager:...:secret:ad-creds")
GOOGLE_SECRET_NAME = os.environ.get("GOOGLE_SECRET_NAME", "arn:aws:secretsmanager:...:secret:google-creds")
S3_BUCKET_NAME = os.environ.get("S3_BUCKET_NAME", "")  # e.g., "company-audit-bucket"
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")  # e.g., "arn:aws:sns:ap-south-1:123456789012:ad-notify"
SHEET_ID = os.environ.get("SHEET_ID", "")  # Google Spreadsheet ID
DRY_RUN = os.environ.get("DRY_RUN", "true").lower() in ("1", "true", "yes")  # safe default: no AD changes

# Constants
GOOGLE_SHEETS_API = "https://sheets.googleapis.com/v4/spreadsheets"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

# --- Helper: Secrets Manager ---
def get_secret(secret_name: str) -> dict:
    """
    Retrieve JSON secret from AWS Secrets Manager.
    Raises exception if secret can't be retrieved.
    """
    client = boto3.client("secretsmanager")
    try:
        resp = client.get_secret_value(SecretId=secret_name)
        secret_str = resp.get("SecretString")
        if not secret_str:
            raise RuntimeError("No SecretString found for secret: " + str(secret_name))
        return json.loads(secret_str)
    except Exception as e:
        logger.exception("Failed to fetch secret %s: %s", secret_name, e)
        raise

def update_secret(secret_name: str, secret_dict: dict):
    """
    Optionally update the Secrets Manager secret (e.g., to store refreshed access_token).
    Use cautiously and make sure lambda role has permission to put-secret-value.
    """
    client = boto3.client("secretsmanager")
    try:
        client.put_secret_value(SecretId=secret_name, SecretString=json.dumps(secret_dict))
        logger.info("Updated secret %s in Secrets Manager", secret_name)
    except Exception:
        logger.exception("Failed to update secret %s", secret_name)

# --- Google Sheets helpers ---
def refresh_access_token(google_secrets: dict) -> str:
    """
    Refresh Google OAuth access token using refresh_token.
    Optionally updates the secrets dict with new access_token for future reuse.
    """
    payload = {
        "client_id": google_secrets.get("client_id"),
        "client_secret": google_secrets.get("client_secret"),
        "refresh_token": google_secrets.get("refresh_token"),
        "grant_type": "refresh_token",
    }
    resp = requests.post(GOOGLE_TOKEN_URL, data=payload, timeout=10)
    if resp.status_code != 200:
        logger.error("Failed to refresh google token: %s", resp.text)
        raise RuntimeError("Google token refresh failed: " + resp.text)
    new_token = resp.json().get("access_token")
    if not new_token:
        raise RuntimeError("No access_token returned from Google token endpoint")
    # Optionally persist updated token back to Secrets Manager for future usage
    google_secrets["access_token"] = new_token
    try:
        # Try updating secrets manager; if this fails, ignore but log.
        update_secret(GOOGLE_SECRET_NAME, google_secrets)
    except Exception:
        logger.debug("Could not update Google secret with new access token (optional).")
    return new_token

def get_sheet_data(sheet_id: str, range_name: str, google_secrets: dict) -> list:
    """
    Fetch a ranges values from Google Sheets API.
    Returns list-of-rows (each row is list of cell strings).
    Raises runtime error on failure.
    """
    access_token = google_secrets.get("access_token") or google_secrets.get("token") or google_secrets.get("client_token")
    headers = {"Authorization": f"Bearer {access_token}"} if access_token else {}
    url = f"{GOOGLE_SHEETS_API}/{sheet_id}/values/{range_name}"
    resp = requests.get(url, headers=headers, timeout=15)

    if resp.status_code == 401:
        logger.info("Access token expired or unauthorized. Attempting refresh.")
        access_token = refresh_access_token(google_secrets)
        headers["Authorization"] = f"Bearer {access_token}"
        resp = requests.get(url, headers=headers, timeout=15)

    if resp.status_code != 200:
        logger.error("Failed to fetch sheet %s range %s: %s", sheet_id, range_name, resp.text)
        raise RuntimeError(f"Failed to fetch sheet: {resp.text}")

    data = resp.json().get("values", [])
    logger.info("Fetched %d rows from %s", len(data), range_name)
    return data

# --- S3 snapshot helper ---
def save_sheet_to_s3(exit_sheet_data, revoked_sheet_data, s3_bucket: str) -> str:
    """
    Save the two lists (exit & revoked) as an Excel file with two sheets and upload to S3.
    Returns the S3 key used.
    """
    if not s3_bucket:
        logger.warning("S3_BUCKET_NAME not set; skipping snapshot upload.")
        return ""

    exit_df = pd.DataFrame(exit_sheet_data, columns=["Date", "ID"]) if exit_sheet_data else pd.DataFrame(columns=["Date", "ID"])
    revoked_df = pd.DataFrame(revoked_sheet_data, columns=["Date", "ID"]) if revoked_sheet_data else pd.DataFrame(columns=["Date", "ID"])

    now = datetime.utcnow()
    date_str = now.strftime("%Y-%m-%d")
    year = now.strftime("%Y")
    month = now.strftime("%m")
    folder_path = f"{year}/{month}/{date_str}/"
    final_filename = f"{date_str}.xlsx"
    s3_key = f"{folder_path}{final_filename}"
    tmp_path = f"/tmp/{final_filename}"

    try:
        with pd.ExcelWriter(tmp_path, engine="openpyxl") as writer:
            exit_df.to_excel(writer, sheet_name="Exit", index=False)
            revoked_df.to_excel(writer, sheet_name="Revoked", index=False)

        s3 = boto3.client("s3")
        # If file exists, we'll just overwrite (S3 object versioning recommended for audit)
        s3.upload_file(tmp_path, s3_bucket, s3_key)
        logger.info("Uploaded snapshot to s3://%s/%s", s3_bucket, s3_key)
        return s3_key
    except Exception:
        logger.exception("Failed to save snapshot to S3")
        raise
    finally:
        # attempt to remove the tmp file
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            logger.debug("Temp file cleanup failed (non-fatal)")

# --- Data cleaning & merging ---
def get_latest_unique_dataframe(data):
    """
    Accepts list-of-lists like [[date_str, id], ...]
    Returns (latest_df, dropped_ids_list).
    latest_df columns: Date (datetime), ID (uppercase string)
    dropped_ids are the IDs that were dropped due to invalid/missing date or missing ID.
    """
    df = pd.DataFrame(data, columns=["Date", "ID"]) if data else pd.DataFrame(columns=["Date", "ID"])
    # Convert to datetime (coerce invalid formats to NaT)
    df["Date"] = pd.to_datetime(df["Date"], errors="coerce")
    # Normalize ID and detect missing
    df["ID"] = df["ID"].astype(str).str.strip()
    mask_invalid = df["Date"].isna() | df["ID"].isna() | (df["ID"] == "") | (df["ID"].str.upper() == "NONE")
    dropped_rows = df[mask_invalid]
    # Extract dropped IDs (upper-case strings)
    dropped_ids = dropped_rows["ID"].dropna().astype(str).str.upper().tolist()
    # Keep only clean rows
    df_clean = df[~mask_invalid].copy()
    df_clean["ID"] = df_clean["ID"].astype(str).str.upper()
    # Keep the most recent row per ID
    latest_df = df_clean.sort_values("Date", ascending=False).drop_duplicates("ID")
    return latest_df, dropped_ids

def get_exit_status_frame(google_secrets: dict, sheet_id: str):
    """
    Read the Exit & Revoked Resignation sheets, save snapshot to S3,
    drop invalid rows, and compute Exit Status:
      - 1 => disable (Exit Date present and later than Revoke Date or Revoke missing)
      - 0 => enable (Revoked after Exit OR only Revoke present)
    Returns merged_frame with columns: ID, Exit Date, Revoke Date, Exit Status
    """
    exit_sheet_data = get_sheet_data(sheet_id, "Exit!A2:B", google_secrets)
    revoked_sheet_data = get_sheet_data(sheet_id, "Revoked Resignation!A2:B", google_secrets)

    # Save a snapshot for audit
    try:
        save_sheet_to_s3(exit_sheet_data, revoked_sheet_data, S3_BUCKET_NAME)
    except Exception:
        logger.warning("Snapshot to S3 failed; continuing processing (non-fatal)")

    exit_df, exit_dropped = get_latest_unique_dataframe(exit_sheet_data)
    revoked_df, revoked_dropped = get_latest_unique_dataframe(revoked_sheet_data)

    all_dropped_ids = set([x.upper() for x in exit_dropped + revoked_dropped if x])
    if all_dropped_ids:
        notify_unstructured_dates(list(all_dropped_ids), SNS_TOPIC_ARN)

    # Filter out dropped IDs
    exit_df = exit_df[~exit_df["ID"].isin(all_dropped_ids)]
    revoked_df = revoked_df[~revoked_df["ID"].isin(all_dropped_ids)]

    # Rename columns
    exit_df = exit_df.rename(columns={"Date": "Exit Date"})
    revoked_df = revoked_df.rename(columns={"Date": "Revoke Date"})

    # Merge outer on ID (some IDs may be present in only one sheet)
    merged = pd.merge(exit_df[["ID", "Exit Date"]], revoked_df[["ID", "Revoke Date"]], on="ID", how="outer")

    # Determine exit status per rules described in original code
    def determine_status(row):
        if pd.isna(row.get("Revoke Date")):
            return 1  # No revoke recorded -> should be disabled (exit)
        if pd.isna(row.get("Exit Date")):
            return 0  # No exit recorded -> should be enabled
        # Both present -> if Exit Date is after Revoke Date -> disable, else enable
        return int(row["Exit Date"] > row["Revoke Date"])

    merged["Exit Status"] = merged.apply(determine_status, axis=1)
    merged = merged[["ID", "Exit Date", "Revoke Date", "Exit Status"]]
    logger.info("Computed exit status for %d IDs", merged.shape[0])
    return merged

# --- Notifications ---
def notify_unstructured_dates(dropped_ids: list, sns_topic_arn: str):
    """
    Notify via SNS that a set of IDs were dropped due to unstructured dates.
    """
    if not dropped_ids:
        return
    msg = f"Please process these users manually due to unstructured date format:\n{', '.join(dropped_ids)}"
    subject = f"Manual Check Required - Unstructured AD Dates - {datetime.utcnow().strftime('%d-%m-%Y')}"
    if sns_topic_arn:
        sns = boto3.client("sns")
        try:
            resp = sns.publish(TopicArn=sns_topic_arn, Subject=subject, Message=msg)
            logger.info("Published unstructured-date notification, MessageId=%s", resp.get("MessageId"))
        except Exception:
            logger.exception("Failed to publish unstructured-date SNS notification")
    else:
        logger.warning("SNS_TOPIC_ARN not configured; cannot notify about unstructured dates. Dropped: %s", dropped_ids)

def publish_summary(sns_topic_arn: str, enabled_list: list, disabled_list: list, invalid_list: list):
    """
    Publish final summary listing which accounts were enabled/disabled/not found.
    """
    now = datetime.utcnow().strftime("%d-%m-%Y")
    subject = f"AD User Status Notification of {now}"
    message = (
        f"The list of disabled users that was enabled by script:\n{', '.join(enabled_list) or 'None'}\n\n"
        f"The list of disabled users that was disabled by script:\n{', '.join(disabled_list) or 'None'}\n\n"
        f"The list of Users that were not found on AD (mentioned in the sheet):\n{', '.join(invalid_list) or 'None'}"
    )
    if sns_topic_arn:
        sns = boto3.client("sns")
        try:
            resp = sns.publish(TopicArn=sns_topic_arn, Subject=subject, Message=message)
            logger.info("Published summary notification, MessageId=%s", resp.get("MessageId"))
        except Exception:
            logger.exception("Failed to publish summary SNS notification")
    else:
        logger.warning("SNS_TOPIC_ARN not set; summary not sent. Summary:\n%s", message)

# --- Main Lambda handler ---
def lambda_handler(event, context):
    """
    Lambda entrypoint.
    """
    start_ts = time.time()
    logger.info("Lambda invoked (DRY_RUN=%s)", DRY_RUN)

    # Validate necessary configuration
    if not SHEET_ID:
        logger.error("SHEET_ID is not configured. Exiting.")
        return {"status": "error", "reason": "SHEET_ID_not_configured"}

    # Load secrets
    try:
        google_secrets = get_secret(GOOGLE_SECRET_NAME)
        ad_secret = get_secret(AD_SECRET_NAME)
    except Exception as e:
        logger.exception("Failed to load secrets. Aborting.")
        return {"status": "error", "reason": "secrets_load_failed", "details": str(e)}

    # Prepare AD helper instance
    ad_domain = ad_secret.get("AD_DOMAIN")
    username = ad_secret.get("USERNAME")
    password = ad_secret.get("PASSWORD")
    host = ad_secret.get("HOST")
    base_dn = ad_secret.get("BASE_DN")  # optional

    if not all([ad_domain, username, password, host]):
        logger.error("AD secret missing expected keys (AD_DOMAIN, USERNAME, PASSWORD, HOST). Aborting.")
        return {"status": "error", "reason": "ad_secret_missing_keys"}

    if ADAP is None:
        logger.error("ADAP class could not be imported. Ensure ad.py exists in package.")
        return {"status": "error", "reason": "ADAP_not_imported"}

    adap = ADAP(AD_DOMAIN=ad_domain, USERNAME=username, PASSWORD=password, HOST=host, base_dn=base_dn)

    conn = None
    enabled_list = []
    disabled_list = []
    invalid_list = []

    try:
        # Connect to AD
        try:
            conn = adap.getConnection()
        except Exception:
            logger.exception("Failed to obtain AD connection; aborting AD operations.")
            conn = None

        # Compute exit status frame
        try:
            exit_status_frame = get_exit_status_frame(google_secrets, SHEET_ID)
        except Exception:
            logger.exception("Failed to compute exit status frame; aborting.")
            exit_status_frame = pd.DataFrame(columns=["ID", "Exit Date", "Revoke Date", "Exit Status"])

        # Iterate and perform actions
        for idx, row in exit_status_frame.iterrows():
            emp_id = str(row["ID"]).strip()
            try:
                desired_status = int(row["Exit Status"])
            except Exception:
                logger.warning("Invalid Exit Status for ID %s: %s. Skipping.", emp_id, row.get("Exit Status"))
                invalid_list.append(emp_id)
                continue

            # Dry run: do not perform LDAP modifies, but log desired actions
            if DRY_RUN:
                logger.info("[DRY_RUN] Would set ID=%s to Exit Status=%s", emp_id, desired_status)
                # Simulate categorization:
                if desired_status == 1:
                    disabled_list.append(emp_id)
                else:
                    enabled_list.append(emp_id)
                continue

            # If no AD connection, skip modifications but collect invalid
            if conn is None:
                logger.error("No AD connection available; cannot modify user %s", emp_id)
                invalid_list.append(emp_id)
                continue

            # Call class method to enable/disable user (class manages lists internally)
            try:
                adap.disableAdUser(conn, emp_id, desired_status)
            except Exception:
                logger.exception("Error processing user %s", emp_id)
                invalid_list.append(emp_id)

        # Collect lists from instance (if not dry-run)
        if not DRY_RUN:
            enabled_list = adap.should_enable_users
            disabled_list = adap.disabled_users
            invalid_list = adap.invalid_user

    finally:
        # Ensure connection close and final SNS publish
        try:
            adap.closeConnection(conn, sns_topic_arn=SNS_TOPIC_ARN)
        except Exception:
            logger.exception("Error while closing AD connection or publishing summary.")

        # Publish summary (for DRY_RUN it will report simulated lists)
        try:
            publish_summary(SNS_TOPIC_ARN, enabled_list, disabled_list, invalid_list)
        except Exception:
            logger.exception("Failed to publish summary")

    total_time = time.time() - start_ts
    logger.info("Lambda finished in %.2f seconds", total_time)
    return {
        "status": "done",
        "dry_run": DRY_RUN,
        "processed": {"enabled": len(enabled_list), "disabled": len(disabled_list), "invalid": len(invalid_list)},
        "time_seconds": total_time,
    }
