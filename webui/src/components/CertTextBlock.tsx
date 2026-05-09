import { Title, Button, ClipboardCopy } from '@patternfly/react-core';

interface Props {
  pemLabel?: string;
  pem?: string | null;
  certText?: string | null;
  downloadFilename?: string;
  onDownload?: () => void;
}

function triggerPemDownload(pem: string, filename: string) {
  const blob = new Blob([pem], { type: 'application/x-pem-file' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Renders certificate PEM (with copy + download) and/or the openssl-style
 * parsed certificate text block.  Pass `onDownload` instead of `pem` when
 * the PEM requires a separate fetch (e.g. /certs/{id}/download).
 */
export function CertTextBlock({ pemLabel = 'Certificate PEM', pem, certText, downloadFilename, onDownload }: Props) {
  const showDownloadBtn = !!onDownload || (!!pem && !!downloadFilename);

  return (
    <div style={{ marginTop: '1.5rem' }}>
      {pem && (
        <div style={{ marginBottom: '1.5rem' }}>
          <Title headingLevel="h2" size="md" style={{ marginBottom: '0.5rem' }}>{pemLabel}</Title>
          <ClipboardCopy isReadOnly isCode hoverTip="Copy" clickTip="Copied" variant="expansion">
            {pem}
          </ClipboardCopy>
          {showDownloadBtn && (
            <Button variant="secondary" size="sm" style={{ marginTop: '0.5rem' }}
              onClick={() => onDownload ? onDownload() : triggerPemDownload(pem!, downloadFilename!)}>
              Download PEM
            </Button>
          )}
        </div>
      )}
      {!pem && showDownloadBtn && (
        <Button variant="secondary" size="sm" style={{ marginBottom: '1rem' }}
          onClick={() => onDownload!()}>
          Download PEM
        </Button>
      )}
      {certText && (
        <div>
          <Title headingLevel="h2" size="md" style={{ marginBottom: '0.5rem' }}>Certificate Details</Title>
          <pre style={{
            fontFamily: 'monospace',
            fontSize: '0.8rem',
            background: 'var(--pf-v6-global--BackgroundColor--200, #f5f5f5)',
            border: '1px solid var(--pf-v6-global--BorderColor--100, #d2d2d2)',
            borderRadius: '4px',
            padding: '1rem',
            overflowX: 'auto',
            whiteSpace: 'pre',
          }}>
            {certText}
          </pre>
        </div>
      )}
    </div>
  );
}
