import React from 'react'

const marks = { aws: 'aws', azure: 'A', gcp: 'G', alibaba: '阿', digitalocean: 'DO', hetzner: 'H', mixed: '⋯', unknown: '?' }

export default function CloudIcon({ cloud }) {
  return <span className={`cloud-icon cloud-icon-${cloud}`} aria-hidden="true">{marks[cloud] || '?'}</span>
}
