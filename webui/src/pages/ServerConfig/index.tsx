import { useEffect, useState } from 'react';
import {
  PageSection,
  Title,
  Spinner,
  Alert,
  CodeBlock,
  CodeBlockCode,
} from '@patternfly/react-core';
import { getConfig, ServerConfig as ServerConfigData } from '../../api/stats';
import { errorMessage } from '../../api/client';

export default function ServerConfig() {
  const [config, setConfig] = useState<ServerConfigData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getConfig()
      .then(setConfig)
      .catch((e: unknown) => setError(errorMessage(e, 'Failed to load config')));
  }, []);

  return (
    <>
      <PageSection>
        <Title headingLevel="h1">Server Configuration</Title>
      </PageSection>
      <PageSection>
        {error && <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />}
        {!config && !error && <Spinner />}
        {config && (
          <CodeBlock>
            <CodeBlockCode>{JSON.stringify(config, null, 2)}</CodeBlockCode>
          </CodeBlock>
        )}
      </PageSection>
    </>
  );
}
