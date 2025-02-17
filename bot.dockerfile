FROM rust:latest
WORKDIR /usr/src/app
COPY ./bot/ .
RUN cargo build --release
CMD ["./target/release/phishing-detector-bot"]
