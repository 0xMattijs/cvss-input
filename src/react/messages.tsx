import { createContext, useContext, useMemo } from 'react';
import type { ReactNode } from 'react';
import { en, resolveMessages } from '../core/messages';
import type { CvssMessages, CvssMessagesInput } from '../core/messages';

const MessagesContext = createContext<CvssMessages>(en);

/** Sets the language of every cvss-input component inside it. */
export function CvssMessagesProvider({
  messages,
  children,
}: {
  /** A full catalog such as `nl`, or a partial one; missing texts come from the enclosing provider or English. */
  messages: CvssMessages | CvssMessagesInput;
  children?: ReactNode;
}) {
  const parent = useContext(MessagesContext);
  const value = useMemo(() => resolveMessages(messages, parent), [messages, parent]);
  return <MessagesContext.Provider value={value}>{children}</MessagesContext.Provider>;
}

/** The catalog in effect: the nearest provider's, with `override` on top. */
export function useCvssMessages(override?: CvssMessages | CvssMessagesInput): CvssMessages {
  const context = useContext(MessagesContext);
  return useMemo(() => (override ? resolveMessages(override, context) : context), [override, context]);
}
