'use strict';

const { completeChat } = require('./llm-client');

function createProviderCompletion({ localConfig, readProviderConfig, localAllowed, complete = completeChat }) {
  const callLocal = async options => {
    if (!localAllowed) throw new Error('Local AI URL is not an allowed loopback address');
    return { ...(await complete({ ...options, config: localConfig })), provider: 'local', model: localConfig.model };
  };

  return async options => {
    const provider = await readProviderConfig();
    if (!provider.apiKey || provider.mode === 'local') return callLocal(options);

    const remoteConfig = { url: provider.baseUrl, model: provider.model, apiKey: provider.apiKey };
    if (provider.mode === 'remote') {
      try {
        return { ...(await complete({ ...options, config: remoteConfig })), provider: 'remote', model: remoteConfig.model };
      } catch (error) {
        if (!localAllowed) throw error;
        return callLocal(options);
      }
    }

    const localResponse = await callLocal(options);
    try {
      const reviewMessages = [
        ...options.messages,
        { role: 'assistant', content: localResponse.content },
        { role: 'user', content: 'Review the preceding draft against the original request and evidence. Correct unsupported or inaccurate claims, preserve supported facts, and return only the final answer in the requested format.' },
      ];
      return { ...(await complete({ ...options, config: remoteConfig, messages: reviewMessages })), provider: 'review', model: remoteConfig.model };
    } catch {
      return localResponse;
    }
  };
}

module.exports = { createProviderCompletion };