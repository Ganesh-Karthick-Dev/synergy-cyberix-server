import axios from 'axios';
import { CustomError } from '../../middlewares/error.middleware';
import { logger } from '../../utils/logger';
import { Service } from '../../decorators/service.decorator';
import fs from 'fs';
import path from 'path';

@Service()
export class ChatService {
  private readonly grokApiUrl: string;
  private readonly grokModel: string;
  private grokApiKey: string;
  private cyberixDocumentation: string = '';

  constructor() {
    // Allow custom API URL via environment variable, default to xAI endpoint
    this.grokApiUrl = process.env.GROK_API_URL || 'https://api.x.ai/v1/chat/completions';
    // Allow custom model name via environment variable (grok-beta was deprecated, use grok-3)
    this.grokModel = process.env.GROK_MODEL || 'grok-3';
    this.grokApiKey = process.env.GROK_API_KEY || process.env.VITE_GROK_API_KEY || '';
    
    if (!this.grokApiKey) {
      logger.warn('⚠️  Grok API key not configured. Chat functionality will not work.');
    } else {
      logger.info(`✅ Grok API configured - URL: ${this.grokApiUrl}, Model: ${this.grokModel}`);
    }

    // Load Cyberix documentation
    this.loadCyberixDocumentation();
  }

  /**
   * Load Cyberix documentation from file
   * Tries multiple paths to find the documentation
   */
  private loadCyberixDocumentation(): void {
    const possiblePaths = [
      // If documentation is in dist folder (where compiled code runs)
      path.join(process.cwd(), 'dist', 'CYBERIX_COMPLETE_DOCUMENTATION.md'),
      // If documentation is in backend root
      path.join(process.cwd(), 'CYBERIX_COMPLETE_DOCUMENTATION.md'),
      // If backend and frontend are siblings
      path.join(process.cwd(), '..', 'cyberix-web', 'CYBERIX_COMPLETE_DOCUMENTATION.md'),
      // Absolute path fallback from dist
      path.join(__dirname, '..', '..', 'CYBERIX_COMPLETE_DOCUMENTATION.md'),
      // Absolute path fallback to frontend
      path.join(__dirname, '..', '..', '..', '..', 'cyberix-web', 'CYBERIX_COMPLETE_DOCUMENTATION.md'),
    ];

    for (const docPath of possiblePaths) {
      try {
        if (fs.existsSync(docPath)) {
          this.cyberixDocumentation = fs.readFileSync(docPath, 'utf-8');
          logger.info(`✅ Cyberix documentation loaded from: ${docPath}`);
          return;
        }
      } catch (error) {
        logger.warn(`Failed to load documentation from ${docPath}:`, error);
      }
    }

    // Fallback: Use a summary if file not found
    this.cyberixDocumentation = this.getDefaultDocumentation();
    logger.warn('⚠️  Cyberix documentation file not found. Using default summary.');
  }

  /**
   * Default documentation summary (fallback)
   */
  private getDefaultDocumentation(): string {
    return `Cyberix is a comprehensive desktop security suite for cybersecurity scanning, vulnerability assessment, and penetration testing.

Key Features:
- Desktop Application built with Electron and React
- 20+ integrated security testing modules
- Kali Linux Integration through WSL
- Real-time scanning with progress tracking
- Comprehensive reporting (PDF, JSON, CSV, HTML)

Security Tools:
- Web Application Scanners: SQLMap, XSStrike, Nikto, Wapiti, WPScan
- Network Scanners: Nmap, Masscan
- Malware Detection: ClamAV, YARA
- System Security: RKHunter, Chkrootkit, Lynis
- Network Analysis: Tshark, Wireshark
- Phishing Detection: Dnstwist

Installation requires Windows 10/11, WSL 2, and Kali Linux.`;
  }

  /**
   * Get system prompt with Cyberix documentation
   */
  private getSystemPrompt(): string {
    return `You are a specialized AI assistant for Cyberix, a comprehensive desktop security suite for cybersecurity scanning, vulnerability assessment, and penetration testing.

IMPORTANT INSTRUCTIONS:
1. You MUST answer questions ONLY based on the following Cyberix documentation.
2. If a question is not related to Cyberix or cannot be answered from this documentation, politely inform the user that you can only help with Cyberix-related questions.
3. Be helpful, professional, and concise.
4. Always stay within the scope of Cyberix-related topics.
5. If asked about something not in the documentation, say you don't have that information but can help with other Cyberix topics.

CYBERIX DOCUMENTATION:
${this.cyberixDocumentation}

Your role:
- Answer questions about Cyberix features, capabilities, installation, usage, and troubleshooting
- Provide accurate information based on the documentation above
- Help users understand how to use Cyberix effectively
- Guide users through installation and setup processes
- Explain security tools and scanning capabilities`;
  }

  /**
   * Send message to Grok API with Cyberix context
   */
  async sendMessage(message: string, conversationHistory: Array<{ sender: string; text: string }> = []): Promise<string> {
    if (!this.grokApiKey) {
      throw new CustomError('Grok API key not configured. Please contact administrator.', 500);
    }

    try {
      // Prepare conversation messages
      const messages: Array<{ role: string; content: string }> = [
        {
          role: 'system',
          content: this.getSystemPrompt()
        },
        // Add conversation history (last 10 messages to avoid token limits)
        ...conversationHistory.slice(-10).map((msg) => ({
          role: msg.sender === 'user' ? 'user' : 'assistant',
          content: msg.text
        })),
        {
          role: 'user',
          content: message
        }
      ];

      logger.info(`[ChatService] Sending message to Grok API (${messages.length} messages in context)`);

      logger.info(`[ChatService] Calling Grok API: ${this.grokApiUrl} with model: ${this.grokModel}`);

      const response = await axios.post(
        this.grokApiUrl,
        {
          model: this.grokModel,
          messages: messages,
          temperature: 0.7,
          max_tokens: 1000,
          stream: false
        },
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.grokApiKey}`
          },
          timeout: 30000 // 30 seconds timeout
        }
      );

      const aiResponse = response.data.choices?.[0]?.message?.content || 
                        response.data.response || 
                        'I apologize, but I could not generate a response. Please try again.';

      logger.info('[ChatService] Successfully received response from Grok API');
      return aiResponse;

    } catch (error: any) {
      logger.error('[ChatService] Error calling Grok API:', error);
      
      // Log detailed error information
      if (error.response) {
        logger.error('[ChatService] Grok API Error Response:', {
          status: error.response.status,
          statusText: error.response.statusText,
          data: error.response.data,
          headers: error.response.headers
        });
      }

      if (error.response) {
        // API returned an error response
        const status = error.response.status;
        const errorData = error.response.data;

        if (status === 401) {
          throw new CustomError('Invalid Grok API key. Please contact administrator.', 500);
        } else if (status === 404) {
          // 404 could mean wrong endpoint or model name
          const errorMsg = errorData?.error?.message || errorData?.message || 'Grok API endpoint or model not found';
          logger.error(`[ChatService] 404 Error Details: ${JSON.stringify(errorData)}`);
          throw new CustomError(
            `Grok API endpoint not found. Please check API URL and model name. Details: ${errorMsg}`,
            404
          );
        } else if (status === 429) {
          throw new CustomError('Rate limit exceeded. Please try again later.', 429);
        } else {
          throw new CustomError(
            errorData?.error?.message || errorData?.message || 'Failed to get response from Grok API',
            status
          );
        }
      } else if (error.request) {
        // Request was made but no response received
        throw new CustomError('No response from Grok API. Please check your connection and try again.', 500);
      } else {
        // Error setting up the request
        throw new CustomError(
          error.message || 'An unexpected error occurred while processing your request.',
          500
        );
      }
    }
  }
}

