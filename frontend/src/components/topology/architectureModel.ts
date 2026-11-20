export interface ArchitectureResource {
  id: string;
  kind: string;
  label: string;
  typeLabel: string;
  icon: string;
  data: Record<string, unknown>;
  subtitle?: string;
  selected?: boolean;
  container?: boolean;
}
export interface ArchitectureRelation { id: string; source: string; target: string; label: string }
export interface ArchitectureModel {
  resources: Record<string, ArchitectureResource>;
  nodes: Array<{ id: string; parentId?: string }>;
  edges: ArchitectureRelation[];
  notices: string[];
}
