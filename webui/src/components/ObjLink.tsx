import { Link } from 'react-router-dom';
import { ObjType, objectPath } from '../utils';

interface Props {
  type: ObjType;
  id: string | null | undefined;
  /** Override link text; defaults to the id itself. */
  label?: string;
}

/**
 * Renders a React Router link to the canonical detail page for the given
 * object type and id.  Renders '—' when id is null/undefined/empty.
 */
export function ObjLink({ type, id, label }: Props) {
  if (!id) return <>—</>;
  return <Link to={objectPath(type, id)}>{label ?? id}</Link>;
}
