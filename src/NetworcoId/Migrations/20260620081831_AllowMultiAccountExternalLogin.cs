using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace NetworcoId.Migrations
{
    /// <inheritdoc />
    public partial class AllowMultiAccountExternalLogin : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_user_external_logins_provider_subject",
                table: "user_external_logins");

            migrationBuilder.CreateIndex(
                name: "IX_user_external_logins_provider_subject",
                table: "user_external_logins",
                columns: new[] { "provider", "subject" });

            migrationBuilder.CreateIndex(
                name: "IX_user_external_logins_provider_subject_user_id",
                table: "user_external_logins",
                columns: new[] { "provider", "subject", "user_id" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_user_external_logins_provider_subject",
                table: "user_external_logins");

            migrationBuilder.DropIndex(
                name: "IX_user_external_logins_provider_subject_user_id",
                table: "user_external_logins");

            migrationBuilder.CreateIndex(
                name: "IX_user_external_logins_provider_subject",
                table: "user_external_logins",
                columns: new[] { "provider", "subject" },
                unique: true);
        }
    }
}
