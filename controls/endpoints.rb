# frozen_string_literal: true

# NIST SC-7 — S3 Gateway Endpoint keeps traffic within AWS network
control 'secure-vpc-07' do
  impact 0.5
  title 'S3 gateway endpoint exists'
  desc 'An S3 gateway endpoint should exist for the VPC to route S3
        traffic through the AWS backbone instead of the internet.'

  tag nist: %w[SC-7]

  vpc_id = input('vpc_id')

  describe aws_vpc_endpoints.where(vpc_id: vpc_id) do
    it { should exist }
  end
end
