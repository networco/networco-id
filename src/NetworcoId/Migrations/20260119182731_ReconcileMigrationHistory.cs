using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace NetworcoId.Migrations
{
    /// <inheritdoc />
    public partial class ReconcileMigrationHistory : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("ALTER TABLE users ADD COLUMN IF NOT EXISTS roles text[] NOT NULL DEFAULT '{}';");
            migrationBuilder.Sql("ALTER TABLE users ADD COLUMN IF NOT EXISTS address_country text;");
            migrationBuilder.Sql("ALTER TABLE users ADD COLUMN IF NOT EXISTS address_formatted text;");
            migrationBuilder.Sql("ALTER TABLE users ADD COLUMN IF NOT EXISTS address_locality text;");
            migrationBuilder.Sql("ALTER TABLE users ADD COLUMN IF NOT EXISTS address_postal_code text;");
            migrationBuilder.Sql("ALTER TABLE users ADD COLUMN IF NOT EXISTS address_region text;");
            migrationBuilder.Sql("ALTER TABLE users ADD COLUMN IF NOT EXISTS address_street_address text;");
            migrationBuilder.Sql("ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_number_verified boolean NOT NULL DEFAULT false;");
            migrationBuilder.Sql("ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS client_id text;");
            
            migrationBuilder.Sql(@"
                CREATE TABLE IF NOT EXISTS system_settings (
                    key character varying(100) NOT NULL,
                    value character varying(1000) NOT NULL,
                    description text,
                    updated_at timestamp with time zone NOT NULL,
                    CONSTRAINT ""PK_system_settings"" PRIMARY KEY (key)
                );");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(name: "system_settings");
            migrationBuilder.DropColumn(name: "client_id", table: "refresh_tokens");
            migrationBuilder.DropColumn(name: "phone_number_verified", table: "users");
            migrationBuilder.DropColumn(name: "address_street_address", table: "users");
            migrationBuilder.DropColumn(name: "address_region", table: "users");
            migrationBuilder.DropColumn(name: "address_postal_code", table: "users");
            migrationBuilder.DropColumn(name: "address_locality", table: "users");
            migrationBuilder.DropColumn(name: "address_formatted", table: "users");
            migrationBuilder.DropColumn(name: "address_country", table: "users");
            migrationBuilder.DropColumn(name: "roles", table: "users");
        }
    }
}
