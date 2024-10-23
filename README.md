# E-Bills

Core for Bitcredit project.

![Bitcredit drawio](https://github.com/BitcoinCredit/E-Bills/assets/57773598/1fd8021d-cc41-408e-8c7e-c256c3bf4f3a)

## Contribute

### Backend

Make sure to have a recent version of the Rust toolchain installed.

Start the backend server in development mode:

```bash
# Run with defaults
cargo run

# configure listening ports and addresses
cargo run -- --http-port 8001 --http-address 0.0.0.0

# Configuration can also be set via environment variables
export P2P_PORT=1909
export P2P_ADDRESS=0.0.0.0
```

### Configuration

You can use the following environment variables to configure the application:

* `P2P_PORT` - the P2P port (default: 1908)
* `P2P_ADDRESS` - the P2P address (default: 0.0.0.0)
* `HTTP_PORT` - the HTTP address (default: 8000)
* `HTTP_ADDRESS` - the HTTP address (default: 127.0.0.1, or 0.0.0.0 in Docker)
* `RUST_LOG` - the log level, e.g.: info, trace, debug, error (default: error)

### Frontend

Make sure to have a recent version of Node.js installed.

Build the frontend:

```bash
cd frontend
npm install --legacy-peer-deps
npm run build
```

### Development

Start the app in development mode with frontend and backend hot reloading (requires two terminals):

```bash
# Terminal 1
cargo watch -x run  # watch can be installed with cargo install cargo-watch

# Terminal 2
cd frontend
npm run start
```

### Docker

The docker build requires no dependencies other than docker or podman. It can also be used
to run multiple instances of the app on different ports for testing the P2P functionality.

#### Build a standalone docker image

Build the image:

```bash
# The image name can be changed to whatever you want
docker build -t <image-name> .
```

Launch the image:

```bash
docker run -p 8000:8000 -p 1908:1908 <image-name>
```

You should be able to open the app at [http://127.0.0.1:8000/bitcredit/]([http://127.0.0.1:8000/bitcredit/])

#### Run with docker-compose

Build and launch the app with docker-compose running on a different port than the default 8000:

```bash
# run in foreground, can be stopped using CTRL+C
docker-compose up

# run in background, can be stopped using docker-compose stop
docker-compose up -d

# rebuild the image
docker-compose build
```

If you use the above commands, the application state (identity, bills, contacts) will persist between sessions. However, if you use `docker-compose down`, or `docker-compose rm`, the existing container gets removed, along with it's state.
Of course, rebuilding the image also removes the application state.

