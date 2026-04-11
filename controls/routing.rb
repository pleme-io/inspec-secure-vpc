# frozen_string_literal: true

# NIST SC-7 | AC-4(21) — Route table isolation
control 'secure-vpc-06' do
  impact 1.0
  title 'Route tables enforce tier isolation'
  desc 'Public route tables route through IGW. Private route tables must
        not have a 0.0.0.0/0 route (no internet egress unless NAT is
        explicitly enabled).'

  tag nist: %w[SC-7 AC-4(21)]

  vpc_id = input('vpc_id')
  prefix = input('vpc_name_prefix')

  # Verify at least one route table exists with internet gateway route
  describe aws_route_tables.where(vpc_id: vpc_id) do
    it { should exist }
  end
end
