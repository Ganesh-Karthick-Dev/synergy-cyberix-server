import { config } from '../config/env.config';

export function getWelcomeBannerHTML(): string {
  const uptime = process.uptime();
  const hours = Math.floor(uptime / 3600);
  const minutes = Math.floor((uptime % 3600) / 60);
  const seconds = Math.floor(uptime % 60);
  const uptimeFormatted = `${hours}h ${minutes}m ${seconds}s`;

  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cyberix Security API Server</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        html, body {
            height: 100%;
            overflow: hidden;
        }
        body {
            font-family: 'Poppins', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #0f0f0f 0%, #1a1a1a 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            color: #333;
        }
        .container {
            background: #ffffff;
            border-radius: 20px;
            box-shadow: 0 30px 80px rgba(0, 0, 0, 0.5);
            max-width: 900px;
            width: 100%;
            padding: 45px 50px;
            animation: fadeIn 0.6s ease-in;
            border: 1px solid rgba(251, 101, 20, 0.08);
            display: flex;
            flex-direction: column;
            max-height: 95vh;
        }
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        .header {
            text-align: center;
            margin-bottom: 35px;
        }
        .logo {
            width: 70px;
            height: 70px;
            background: linear-gradient(135deg, #fb6514 0%, #ff8c42 100%);
            border-radius: 18px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            box-shadow: 0 10px 30px rgba(251, 101, 20, 0.35);
        }
        .logo svg {
            width: 40px;
            height: 40px;
            fill: white;
        }
        h1 {
            font-size: 2.25rem;
            color: #1a1a1a;
            margin-bottom: 8px;
            font-weight: 700;
            letter-spacing: -0.3px;
        }
        .subtitle {
            font-size: 1rem;
            color: #666;
            margin-bottom: 18px;
            font-weight: 400;
        }
        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
            padding: 6px 18px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
        }
        .status-badge::before {
            content: '●';
            font-size: 10px;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% {
                opacity: 1;
            }
            50% {
                opacity: 0.6;
            }
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 30px;
        }
        .info-card {
            background: #ffffff;
            padding: 20px 18px;
            border-radius: 12px;
            border: 1px solid #f0f0f0;
            transition: all 0.2s ease;
            position: relative;
        }
        .info-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 3px;
            height: 100%;
            background: linear-gradient(135deg, #fb6514 0%, #ff8c42 100%);
            border-radius: 12px 0 0 12px;
        }
        .info-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(251, 101, 20, 0.12);
            border-color: rgba(251, 101, 20, 0.2);
        }
        .info-card h3 {
            font-size: 0.7rem;
            color: #999;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
            font-weight: 600;
        }
        .info-card p {
            font-size: 1.35rem;
            color: #1a1a1a;
            font-weight: 700;
            letter-spacing: -0.3px;
        }
        .footer {
            text-align: center;
            padding-top: 25px;
            border-top: 1px solid #f0f0f0;
            color: #666;
            font-size: 0.85rem;
            margin-top: auto;
        }
        .footer p {
            margin-bottom: 10px;
        }
        .footer strong {
            color: #fb6514;
            font-weight: 600;
        }
        .footer-links {
            display: flex;
            justify-content: center;
            gap: 24px;
            margin-top: 12px;
            flex-wrap: wrap;
        }
        .footer-links a {
            color: #fb6514;
            text-decoration: none;
            font-weight: 500;
            font-size: 0.9rem;
            transition: all 0.2s ease;
            position: relative;
        }
        .footer-links a::after {
            content: '';
            position: absolute;
            bottom: -2px;
            left: 0;
            width: 0;
            height: 1.5px;
            background: #fb6514;
            transition: width 0.2s ease;
        }
        .footer-links a:hover::after {
            width: 100%;
        }
        .footer-links a:hover {
            color: #ff8c42;
        }
        .timestamp {
            margin-top: 12px;
            font-size: 0.75rem;
            color: #aaa;
        }
        @media (max-width: 768px) {
            .container {
                padding: 35px 30px;
            }
            .info-grid {
                grid-template-columns: repeat(2, 1fr);
                gap: 12px;
            }
            h1 {
                font-size: 1.85rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">
                <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path d="M12 1L3 5V11C3 16.55 6.84 21.74 12 23C17.16 21.74 21 16.55 21 11V5L12 1M10 17L6 13L7.41 11.59L10 14.17L16.59 7.58L18 9L10 17Z"/>
                </svg>
            </div>
            <h1>Cyberix Security API</h1>
            <p class="subtitle">Enterprise-Grade Cybersecurity Platform Backend</p>
            <span class="status-badge">Server Online</span>
        </div>

        <div class="info-grid">
            <div class="info-card">
                <h3>Environment</h3>
                <p>${config.nodeEnv.toUpperCase()}</p>
            </div>
            <div class="info-card">
                <h3>Uptime</h3>
                <p>${uptimeFormatted}</p>
            </div>
            <div class="info-card">
                <h3>Port</h3>
                <p>${config.port}</p>
            </div>
            <div class="info-card">
                <h3>Version</h3>
                <p>1.0.0</p>
            </div>
        </div>

        <div class="footer">
            <p>Powered by <strong>Cyberix Security Team</strong></p>
            <div class="footer-links">
                <a href="/health">Health Check</a>
                <a href="/api">API Documentation</a>
            </div>
            <p class="timestamp">
                Server started at ${new Date().toLocaleString()}
            </p>
        </div>
    </div>
</body>
</html>
  `;
}

