require 'omniauth-oauth'
require 'rexml/document'
require 'jwt'

module OmniAuth
  module Strategies
    class Mediawiki < OmniAuth::Strategies::OAuth
      option :name, "mediawiki"

      def self.site
        if ENV['WIKI_AUTH_SITE']
          ENV['WIKI_AUTH_SITE']
        else
          "https://www.mediawiki.org"
        end
      end
      
      def self.oauth
        if ENV['WIKI_AUTH_OAUTH']
          ENV['WIKI_AUTH_OAUTH']
        else
          "Special:OAuth"
        end
      end
      
      def self.script
        if ENV['WIKI_AUTH_SCRIPT']
          ENV['WIKI_AUTH_SCRIPT']
        else
          "/w"
        end
      end

      option :client_options, {
        :site => site,
        :authorize_path => "%s/index.php?title=%s/authorize" % [script, oauth],
        :access_token_path => "%s/index.php?title=%s/token" % [script, oauth],
        :request_token_path => "%s/index.php?title=%s/initiate" % [script, oauth]
      }

      # These are called after authentication has succeeded. If
      # possible, you should try to set the UID without making
      # additional calls (if the user id is returned with the token
      # or as a URI parameter). This may not be possible with all
      # providers.
      uid{ raw_info["sub"] }

      info do
        {
          :name => raw_info["username"],
          :email => raw_info["email"],
          :urls => {"server" => raw_info["iss"]}
        }
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end


      def raw_info
        @raw_info ||= parse_info(access_token.get("%s/index.php?title=%s/identify" % [script, oauth]))

        @raw_info
      end
      
      private
      
      def parse_info(jwt_data)
        ident = jwt_data.body
        payload, header = JWT.decode(ident, consumer.secret)
        
        payload
      end

    end
  end
end
