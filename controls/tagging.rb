# frozen_string_literal: true

# NIST AC-4 | SC-7 — TrustBoundary tagging for boundary identification
control 'secure-vpc-08' do
  impact 0.5
  title 'VPC has TrustBoundary=zero-trust tag'
  desc 'The VPC and all network resources must be tagged with
        TrustBoundary=zero-trust for boundary identification.'

  tag nist: %w[AC-4 SC-7]

  vpc_id = input('vpc_id')

  describe aws_vpc(vpc_id) do
    it { should exist }
    its('tags') { should include('TrustBoundary' => 'zero-trust') }
  end
end
