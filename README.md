# E-Bills

Core for Bitcredit project.

![Bitcredit drawio](https://github.com/BitcoinCredit/E-Bills/assets/57773598/1fd8021d-cc41-408e-8c7e-c256c3bf4f3a)

## Contribute

### Backend

Make sure to have a recent version of the Rust toolchain installed.

Start the backend server in development mode:

```bash
cargo run
```

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
docker run -p 8000:8000 <image-name>
```

#### Run with docker-compose

Build and launch the app with docker-compose running on a different port that the default 8000:

```bash
# run in foreground
docker-compose up

# run in background
docker-compose up -d

# rebuild the image
docker-compose build
```
