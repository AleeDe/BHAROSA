/** Message kinds this application currently ingests. */
export type SupportedMessageType = "text" | "image" | "unsupported";

/** A WhatsApp message normalized into the shape the app works with. */
export interface IncomingMessage {
  id: string;
  chatId: string;
  type: SupportedMessageType;

  text?: string;

  image?: {
    filePath: string;
    mimeType?: string;
    caption?: string;
  };
}
