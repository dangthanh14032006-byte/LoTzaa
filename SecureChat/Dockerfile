# ---- Build stage ----
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy toàn bộ mã nguồn (Core, Server, Client, SecureChat.Web, SecureChat.sln)
COPY . .

WORKDIR /src/SecureChat.Web
RUN dotnet restore
RUN dotnet publish -c Release -o /app/publish --no-restore

# ---- Runtime stage ----
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .

ENV ASPNETCORE_ENVIRONMENT=Production
EXPOSE 8080

# Render tiêm biến PORT lúc container chạy (khác nhau mỗi lần deploy) -> cần
# đọc $PORT tại runtime bằng shell, không thể hardcode trong ENTRYPOINT dạng mảng.
ENTRYPOINT ["/bin/sh", "-c", "ASPNETCORE_URLS=http://+:$PORT dotnet SecureChat.Web.dll"]
