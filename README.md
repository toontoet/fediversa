# FediVersa

FediVersa is a bridge application designed to synchronize posts between Mastodon and Bluesky accounts. It monitors your linked accounts on both platforms and automatically cross-posts new content.

## Features

*   **Bi-directional Syncing:** Posts from Mastodon are synced to Bluesky, and posts from Bluesky are synced to Mastodon.
*   **Media Handling:** Images attached to posts are downloaded and re-uploaded to the target platform.
*   **Web Interface:** A simple web UI allows linking accounts via OAuth (Mastodon) or App Password (Bluesky) and displays basic sync statistics.
*   **Configurable Sync Interval:** Set how often the application checks for new posts (default: 5 minutes).
*   **Database Migrations:** Uses `golang-migrate` to manage database schema changes automatically.
*   **Docker Support:** Includes a `Dockerfile` for easy containerized deployment.

## Prerequisites

*   **Go:** Version 1.21 or higher.
*   **SQLite:** The application uses SQLite, but the necessary C libraries are typically included with Go or handled by the Docker image.
*   **Mastodon Account:** An account on a Mastodon instance.
*   **Bluesky Account:** A Bluesky account with an **App Password** generated (Go to Bluesky Settings -> App Passwords).

## Configuration

FediVersa is configured using environment variables or a `.env` file in the project root. Create a `.env` file by copying `.env.example` and filling in the values:

```bash
cp .env.example .env
```

**Required Configuration:**

*   `MASTODON_SERVER`: The full URL of your Mastodon instance (e.g., `https://mastodon.social`).
*   `BASE_URL`: The public URL where FediVersa is running. This is crucial for Mastodon OAuth redirects (e.g., `http://your-server-ip:8080` or `https://fediversa.yourdomain.com`).

**Bluesky Credentials:**

You will enter your Bluesky Identifier (handle or email) and **App Password** via the web interface after starting the application. These are then stored securely in the database. **Do not** put your main Bluesky password in the configuration.

**Mastodon Credentials:**

`MASTODON_CLIENT_ID` and `MASTODON_CLIENT_SECRET` are obtained *after* you successfully link your Mastodon account via the web interface for the first time. The application will guide you through the Mastodon OAuth flow. The access token obtained will be stored in the database. You might need to register the application manually on your Mastodon instance first if the automatic flow has issues (check Mastodon settings -> Development).

**Optional Configuration:**

*   `DATABASE_PATH`: Path to the SQLite database file (default: `fediversa.db` or `/app/db/fediversa.db` in Docker).
*   `SYNC_INTERVAL_MINUTES`: Interval for checking posts (default: `5`).
*   `LISTEN_ADDR`: Network address and port for the web UI (default: `:8080`).
*   `SYNC_BOOSTS_REPOSTS`: Set to false to prevent syncing Mastodon boosts (default: true). Note: Bluesky reposts are currently never synced.
*   `SYNC_REPLIES`: Set to false to disable syncing replies made to *other people's* posts (default: true). Handling of replies to your *own* posts (threads) is part of future improvements.

**Important:** Add your `.env` file to your `.gitignore` if it's not already there to avoid committing secrets.

### Mastodon Application Setup

1.  Go to your Mastodon instance's settings: `Preferences` -> `Development`.
2.  Click `New Application`.
3.  Fill in the details:
    *   **Application Name:** Choose a name (e.g., "FediVersa Sync").
    *   **Application Website:** Optional, you can use the `BASE_URL` of your FediVersa instance.
    *   **Redirect URIs:** This is crucial. Enter the callback URL for FediVersa. It depends on the `BASE_URL` you set in your `.env` file. The format is:
        ```
        [Your FediVersa Base URL]/auth/mastodon/callback
        ```
        - If you are running FediVersa locally with the default `BASE_URL` (`http://localhost:8080`), enter **exactly**:
          ```
          http://localhost:8080/auth/mastodon/callback
          ```
        - **Make sure this URL exactly matches your FediVersa `BASE_URL` setting (including http/https, host, port if needed) and uses the correct `/auth/mastodon/callback` path.** Any mismatch will cause an `invalid_grant` error during login.
    *   **Scopes:** Select at least `read`, `write`, and `follow`. These permissions are required for FediVersa to read your posts, post on your behalf, and potentially resolve mentions.
4.  Click `Save application`.
5.  Copy the `Client key` and `Client secret` displayed on the next page.
6.  Add these values to your `.env` file:
    ```env
    MASTODON_CLIENT_ID=Your_Client_Key_Here
    MASTODON_CLIENT_SECRET=Your_Client_Secret_Here
    ```

### Bluesky Application Password

# ... rest of README ...

## Building and Running

### Local Development

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd fediversa
    ```
2.  **Install dependencies:**
    ```bash
    go mod tidy
    ```
3.  **Configure:** Create and fill in your `.env` file as described above.
4.  **Run the application:**
    ```bash
    go run cmd/fediversa/main.go
    ```
    The application will start, apply database migrations, and the web UI will be available (usually at `http://localhost:8080` unless `LISTEN_ADDR` is changed).

5.  **Build binary:**
    ```bash
    go build -o fediversa cmd/fediversa/main.go
    ```
    Then run `./fediversa`.

### Docker

1.  **Build the Docker image:**
    ```bash
    docker build -t fediversa:latest .
    ```
2.  **Run the Docker container:**

    You need to pass the environment variables and map volumes for persistent data (database and media).

    ```bash
    docker run -d --name fediversa \
        -p 8080:8080 \
        -v $(pwd)/data/db:/app/db \        # Mount volume for database
        -v $(pwd)/data/media:/app/media \    # Mount volume for media cache
        -e MASTODON_SERVER="https://your.mastodon.instance" \
        -e BASE_URL="http://<your_external_ip_or_domain>:8080" \
        # Add other env vars like MASTODON_CLIENT_ID/SECRET if needed after first run
        --restart unless-stopped \
        fediversa:latest
    ```

    *   Replace `https://your.mastodon.instance` and `http://<your_external_ip_or_domain>:8080` with your actual values.
    *   Ensure the `./data/db` and `./data/media` directories exist locally or adjust the paths as needed.
    *   The `DATABASE_PATH` inside the container defaults to `/app/db/fediversa.db`.

## Usage

1.  **Start the application** (locally or via Docker).
2.  **Access the Web UI:** Open your browser to the `BASE_URL` (e.g., `http://localhost:8080`).
3.  **Link Bluesky Account:**
    *   Enter your Bluesky **Identifier** (handle or email) and your generated **App Password**.
    *   Click "Link BlueSky Account".
4.  **Link Mastodon Account:**
    *   Click the "Link Mastodon Account (OAuth)" button.
    *   You will be redirected to your Mastodon instance to authorize the application.
    *   Grant authorization. You will be redirected back to FediVersa.
    *   The application should now show both accounts as linked. Mastodon Client ID and Secret might be automatically configured/updated in your `.env` or database (depending on implementation details - check logs/DB if needed).
5.  **Synchronization:** The application will now periodically check for new posts (based on `SYNC_INTERVAL_MINUTES`) and sync them between the linked accounts. Check the application logs for details on the sync process.

## Roadmap / TODO

*   Implement full Mastodon OAuth flow. (Done, needs testing/refinement)
*   Implement content transformation logic (`internal/transform`).
*   Handle Mastodon token refresh.
*   Handle Bluesky session refresh.
*   Improve media handling (alt text, video support details).
*   Support syncing replies and boosts/reposts (optional/configurable).
*   More robust error handling and retry logic.
*   Add more detailed statistics to the web UI.
*   Implement user management for multiple bridges (future).
*   Use a proper HTML sanitizer like bluemonday.
*   Secure session cookie storage.
*   Add tests.

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## Disclaimer

**Please Note:** This codebase was primarily generated by Google's Gemini AI model in a pair-programming session with the user.

This project serves as a **proof-of-concept (PoC)** and is experimental in nature. While efforts were made to create functional code, it is provided **"as-is" without any warranties or guarantees** of any kind, express or implied.

The code may contain bugs, inefficiencies, security vulnerabilities, or may not function as expected.

**Use at Your Own Risk:** Anyone using, modifying, or deploying this code does so entirely at their own risk. The AI model and its developers assume **no liability** for any damages, data loss, or other issues that may arise from the use of this software.