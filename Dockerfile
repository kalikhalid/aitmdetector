FROM rust:latest
WORKDIR /usr/src/app
COPY ./api/ .
RUN cargo build --release
CMD ["./target/release/api"]
